package main

import (
	"context"
	"encoding/base64"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/antihax/goesi"
	"github.com/antihax/goesi/esi"
	"github.com/antihax/goesi/optional"
	neucoreapi "github.com/bravecollective/neucore-api-go"
	"github.com/go-yaml/yaml"
	"github.com/slack-go/slack"
	"golang.org/x/exp/slices"
	"golang.org/x/exp/slog"
	"golang.org/x/oauth2"
)

const dateTimeFormat = "2006-01-02 15:04"
const (
	// ceo notifictaions
	CheckNotifs    = "Notifications"
	NotifAnchoring = "StructureAnchoring"
	NotifOnlining  = "StructureOnlining"
	NotifWarStatus = "WarStatus"

	CheckCorps      = "Corporation"
	CorpTaxRate     = "TaxRate"
	CorpWarEligible = "WarEligible"

	CheckChars  = "Characters"
	CharsExist  = "Exists"
	CharsValid  = "ValidToken"
	CharsMember = "MemberStatus"
)

var requiredRoles = [...]neucoreapi.Role{neucoreapi.APP, neucoreapi.APP_CHARS, neucoreapi.APP_ESI, neucoreapi.APP_GROUPS}

func min[T ~int](a, b T) T {
	if a <= b {
		return a
	}
	return b
}

type config struct {
	NeucoreAppID            uint                       `yaml:"NeucoreAppID"`
	Threads                 int                        `yaml:"Threads" default:"20"`
	CorpBaseTaxRate         float32                    `yaml:"CorpBaseTaxRate"`
	RequestTimeoutInSeconds uint                       `yaml:"RequestTimeoutInSeconds" default:"120"`
	NeucoreHTTPScheme       string                     `yaml:"NeucoreHTTPScheme" default:"http"`
	NeucoreDomain           string                     `yaml:"NeucoreDomain"`
	NeucoreAppSecret        string                     `yaml:"NeucoreAppSecret"`
	NeucoreUserAgent        string                     `yaml:"NeucoreUserAgent"`
	NeucoreAPIBase          string                     `yaml:"-"`
	EsiUserAgent            string                     `yaml:"EsiUserAgent"`
	SlackWebhookURL         string                     `yaml:"SlackWebhookURL"`
	CheckAlliances          []int32                    `yaml:"CheckAlliances"`
	CheckCorps              []int32                    `yaml:"CheckCorps"`
	IgnoreCorps             []int32                    `yaml:"IgnoreCorps"`
	IgnoreChars             []int32                    `yaml:"IgnoreChars"`
	Checks                  map[string]map[string]bool `yaml:"Checks"`
}

type app struct {
	config           config
	esi              *goesi.APIClient
	proxyEsi         *goesi.APIClient
	neu              *neucoreapi.APIClient
	neucoreContext   context.Context
	proxyAuthContext context.Context
	startTime        time.Time
	logger           *slog.Logger
}

type corpVerificationResult struct {
	CorpID      int32
	MemberCount int32
	CorpName    string
	Ceo         *neucoreapi.Character
	CeoMain     *neucoreapi.Character
	Errors      []string
	Warnings    []string
	Info        []string
	Status      []string
}

func (app *app) perfTime(msg string, t *time.Time) {
	if t == nil {
		tt := time.Now()
		t = &tt
	}
	app.logger.Info(msg, slog.Duration("duration", time.Since(*t)))
}

func (app *app) initApp() error {
	defer app.perfTime("initApp", nil)

	// read command line flags to get config file, then parse into app.config
	var configFile string
	flag.StringVar(&configFile, "f", "./config.yaml", "Config file to use")
	var notifWarEligible, notifStructure bool
	flag.BoolVar(&notifWarEligible, "notif-war", false, "Check for changes in war eligibility status")
	flag.BoolVar(&notifStructure, "notif-structure", false, "Check for anchoring or onlining structures")
	var corpTaxRate, corpWarEligible bool
	flag.BoolVar(&corpWarEligible, "corp-tax", false, "Check that corp tax rates matches minimum")
	flag.BoolVar(&corpTaxRate, "corp-war", false, "Check that corps are not war eligible")
	var charExists, charValid, charMemberRole bool
	flag.BoolVar(&charExists, "char-exists", false, "Check that the character exists in neucore")
	flag.BoolVar(&charValid, "char-valid", false, "Check that all alts in neucore have a valid esi token")
	flag.BoolVar(&charMemberRole, "char-member-role", false, "Check at least one character has the 'member' neucore role")
	flag.Parse()

	// Read in config file into app.config
	var data []byte
	var err error
	if data, err = os.ReadFile(configFile); err != nil {
		app.logger.Error("error reading config file", slog.String("configFile", configFile), slog.Any("error", err))
		return err
	}
	if err = yaml.Unmarshal(data, &app.config); err != nil {
		app.logger.Error("error parsing config file", slog.String("configFile", configFile), slog.Any("error", err))
		return err
	}
	app.config.NeucoreAPIBase = fmt.Sprintf("%s://%s/api", app.config.NeucoreHTTPScheme, app.config.NeucoreDomain)

	// overwrite check flags with command line settings (if set)
	flag.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "notif-war":
			app.config.Checks[CheckNotifs][NotifWarStatus] = notifWarEligible
		case "notif-structure":
			app.config.Checks[CheckNotifs][NotifAnchoring] = notifStructure
			app.config.Checks[CheckNotifs][NotifOnlining] = notifStructure
		case "corp-tax":
			app.config.Checks[CheckCorps][CorpTaxRate] = corpTaxRate
		case "corp-war":
			app.config.Checks[CheckCorps][CorpWarEligible] = corpWarEligible
		case "char-exists":
			app.config.Checks[CheckChars][CharsExist] = charExists
		case "char-valid":
			app.config.Checks[CheckChars][CharsValid] = charValid
		case "char-member-role":
			app.config.Checks[CheckChars][CharsMember] = charMemberRole
		}
	})
	app.logger.Info("will perform the following", slog.Any("checks", app.config.Checks))

	// Init ESI
	httpc := &http.Client{Timeout: time.Second * time.Duration(app.config.RequestTimeoutInSeconds)}
	app.esi = goesi.NewAPIClient(httpc, app.config.EsiUserAgent)

	// Init Neucore ESI Proxy
	app.proxyEsi = goesi.NewAPIClient(httpc, app.config.NeucoreUserAgent)
	app.proxyEsi.ChangeBasePath(app.config.NeucoreAPIBase + "/app/v2/esi")
	proxyAuth := goesi.NewSSOAuthenticatorV2(httpc, "", "", "", []string{})
	neucoreTokenSource := proxyAuth.TokenSource(&oauth2.Token{
		AccessToken: base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%d:%s", app.config.NeucoreAppID, app.config.NeucoreAppSecret))),
		TokenType:   "bearer",
	})
	app.proxyAuthContext = context.WithValue(context.Background(), goesi.ContextOAuth2, neucoreTokenSource)

	// Init Neucore API
	app.neu = neucoreapi.NewAPIClient(&neucoreapi.Configuration{
		HTTPClient: httpc,
		UserAgent:  app.config.NeucoreUserAgent,
		Servers: neucoreapi.ServerConfigurations{{
			URL:         app.config.NeucoreAPIBase,
			Description: "Neucore API Base",
		}},
		OperationServers: map[string]neucoreapi.ServerConfigurations{},
	})
	app.neucoreContext = context.WithValue(context.Background(), neucoreapi.ContextOAuth2, neucoreTokenSource)
	return nil
}

func main() {
	opts := &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}
	app := app{
		startTime: time.Now(),
		logger:    slog.New(slog.NewTextHandler(os.Stdout, opts)),
	}
	defer app.perfTime("completed execution", &app.startTime)
	slog.SetDefault(app.logger)
	app.logger.Info("starting process...")

	// load config
	if err := app.initApp(); err != nil {
		os.Exit(1)
	}

	// Perform ESI Health check.
	var blocks []slack.Block
	generalErrors, err := app.esiHealthCheck()
	if err != nil {
		app.generateAndSendWebhook(generalErrors, blocks)
		return
	}

	// Neucore Roles Check
	neucoreAppData, _, err := app.neu.ApplicationApi.ShowV1(app.neucoreContext).Execute()
	if err != nil {
		neucoreError := fmt.Sprintf("Error checking neucore app info. error=\"%s\"", err.Error())
		log.Print(neucoreError)
		generalErrors = append(generalErrors, neucoreError)
		app.generateAndSendWebhook(generalErrors, blocks)
		return
	}

	for _, rr := range requiredRoles {
		success := false
		for _, role := range neucoreAppData.Roles {
			if rr == role {
				success = true
			}
		}
		if !success {
			// dump and die
			msg := fmt.Sprintf("Neucore Config Error - Missing Roles:\nGiven: %v\nReq'd: %v", neucoreAppData.Roles, requiredRoles)
			log.Print(msg)
			generalErrors = append(generalErrors, msg)
			app.generateAndSendWebhook(generalErrors, blocks)
			return
		}
	}
	log.Printf("API Check Complete: %f", time.Since(app.startTime).Seconds())

	// Compile a list of all corps to check
	var allCorps []int32
	allCorps = append(allCorps, app.config.CheckCorps...)

	// Get alliance's corp list
	queue := make(chan int32, len(app.config.CheckAlliances))
	mutex := &sync.Mutex{}
	wg := sync.WaitGroup{}
	for i := 0; i < app.config.Threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for allianceID := range queue {
				allianceCorps, _, err := app.esi.ESI.AllianceApi.GetAlliancesAllianceIdCorporations(context.TODO(), allianceID, nil)
				if err != nil {
					logline := fmt.Sprintf("ESI: Error getting alliance corp list for allianceID=%d error=\"%s\"", allianceID, err.Error())
					// dump and exit
					generalErrors = append(generalErrors, logline)
					break
				}
				mutex.Lock()
				allCorps = append(allCorps, allianceCorps...)
				mutex.Unlock()
			}
		}()
	}

	for _, v := range app.config.CheckAlliances {
		queue <- v
	}
	close(queue)

	wg.Add(1)
	financeTokens := make(map[int32]bool)
	go func() {
		defer wg.Done()
		neucoreTokenData, resp, err := app.neu.ApplicationESIApi.EsiEveLoginTokenDataV1(app.neucoreContext, "finance").Execute()
		if err != nil || resp.StatusCode != http.StatusOK {
			eString := "nil"
			if err != nil {
				eString = err.Error()
			}
			generalErrors = append(generalErrors, fmt.Sprintf("Neucore: Error getting finance token data statusCode=%d error=%s", resp.StatusCode, eString))
		}
		for _, v := range neucoreTokenData {
			financeTokens[v.GetCorporationId()] = true
		}
		delete(financeTokens, 0)
	}()

	wg.Wait()
	log.Printf("Alliance Check Complete: %f", time.Since(app.startTime).Seconds())

	// check each corp in the alliance
	queueLength := len(allCorps)
	queue = make(chan int32, queueLength)
	for i := 0; i < app.config.Threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for corpID := range queue {
				if slices.Contains(app.config.IgnoreCorps, corpID) {
					log.Printf("Ignored Corporation id=%d", corpID)
					continue
				}

				corpResult := app.verifyCorporation(corpID, app.config.IgnoreChars, app.startTime)

				if len(financeTokens) > 0 {
					if tok, ok := financeTokens[corpID]; !ok || (ok && !tok) {
						corpResult.Errors = append([]string{"Corporation missing finance token"}, corpResult.Errors...)
					}
				}

				resultWorthLogging := len(corpResult.Errors) > 0 ||
					len(corpResult.Warnings) > 0 ||
					len(corpResult.Info) > 0 ||
					len(corpResult.Status) > 0
				if resultWorthLogging {
					corpBlocks := createCorpBlocks(corpResult)
					mutex.Lock()
					blocks = append(blocks, corpBlocks...)
					mutex.Unlock()
				}
			}
		}()
	}

	for i := 0; i < queueLength; i++ {
		queue <- allCorps[i]
	}
	close(queue)
	wg.Wait()
	log.Printf("Corp Check Complete: %f", time.Since(app.startTime).Seconds())

	app.generateAndSendWebhook(generalErrors, blocks)
}

func (app *app) verifyCorporation(corpID int32, charIgnoreList []int32, startTime time.Time) *corpVerificationResult {
	now := time.Now()
	results := &corpVerificationResult{
		CorpID:   corpID,
		CorpName: fmt.Sprintf("Corp %d", corpID),
		Ceo:      &neucoreapi.Character{Name: "CEO"},
		CeoMain:  &neucoreapi.Character{Name: "???"},
	}

	// Get public corp data
	corpData, _, err := app.esi.ESI.CorporationApi.GetCorporationsCorporationId(context.TODO(), corpID, nil)
	if err != nil {
		logline := fmt.Sprintf("ESI: Error getting public corp info. corpID=%d error=\"%s\"", corpID, err.Error())
		log.Print(logline)
		results.Errors = append(results.Errors, "Error getting public corp info.")
		return results
	}
	results.CorpName = corpData.Name
	results.MemberCount = corpData.MemberCount
	ceoId := int64(corpData.CeoId)
	results.Ceo.Id = *neucoreapi.NewNullableInt64(&ceoId)
	results.Ceo.Name = fmt.Sprintf("%d", corpData.CeoId)
	log.Printf("Corp Data retrieved after %f corpID=%d", time.Since(startTime).Seconds(), corpID)

	// Get CEO info from neucore
	neuMain, response, err := app.neu.ApplicationCharactersApi.MainV2(app.neucoreContext, corpData.CeoId).Execute()
	if err != nil {
		logline := "Neu: Error retreiving CEO's main."
		if response == nil {
			logline = logline + fmt.Sprintf(" ceoID=%d corpID=%d httpResponse=nil error=\"%s\"", corpID, corpData.CeoId, err.Error())
			results.Errors = append(results.Errors, logline)
			log.Print(logline)
			return results
		}
		logline = logline + fmt.Sprintf(" ceoID=%d corpID=%d status=\"%s\" error=\"%s\"", corpID, corpData.CeoId, response.Status, err.Error())
		log.Print(logline)

		switch response.StatusCode {
		case http.StatusNotFound:
			results.Errors = append(results.Errors, "CEO or CEO's main not found in Neucore.")
		default:
			results.Errors = append(results.Errors, logline)
		}
		return results
	}
	results.CeoMain = neuMain

	///
	/// Check CEO's notifications (cached 10 minutes)
	///
	if len(app.config.Checks[CheckCorps]) > 0 {
		app.checkCeoNotifications(corpID, &corpData, results, now, startTime)
	}

	///
	/// Check corp info and member lists (cached 1 hour)
	///
	if app.config.Checks[CheckCorps][CorpTaxRate] && corpData.TaxRate < app.config.CorpBaseTaxRate {
		results.Errors = append(results.Errors, fmt.Sprintf("Tax rate is %.f%% (expected at least %.f%%)", corpData.TaxRate*100, app.config.CorpBaseTaxRate*100))
	}
	if app.config.Checks[CheckCorps][CorpWarEligible] && corpData.WarEligible {
		results.Errors = append(results.Errors, "Corporation is War Eligible.")
	}
	if len(app.config.Checks[CheckChars]) > 0 {
		app.discoverNaughtyMembers(corpID, &corpData, results, charIgnoreList, startTime)
	}

	return results
}

func (app *app) checkCeoNotifications(corpID int32, corpData *esi.GetCorporationsCorporationIdOk, results *corpVerificationResult, now time.Time, startTime time.Time) {
	ceoStringID := optional.NewString(results.Ceo.Name)
	notificationOps := &esi.GetCharactersCharacterIdNotificationsOpts{Datasource: ceoStringID}
	notifications, response, err := app.proxyEsi.ESI.CharacterApi.GetCharactersCharacterIdNotifications(app.proxyAuthContext, corpData.CeoId, notificationOps)
	if err != nil {
		logline := "Proxy: Error getting CEO's notifications."
		if response == nil {
			logline = logline + fmt.Sprintf(" corpID=%d ceoID=%d httpResponse=nil error=\"%s\"", corpID, corpData.CeoId, err.Error())
			results.Errors = append(results.Errors, logline)
			log.Print(logline)
			return
		}
		logline = logline + fmt.Sprintf(" corpID=%d ceoID=%d status=\"%s\" error=\"%s\"", corpID, corpData.CeoId, response.Status, err.Error())
		log.Print(logline)

		switch response.StatusCode {
		case http.StatusForbidden:
			results.Warnings = append(results.Warnings, "Re-auth corp CEO: Needs ESI scope for notifications.")
		default:
			results.Warnings = append(results.Warnings, logline)
		}
	}

	for _, notif := range notifications {
		if notif.Timestamp.Add(time.Hour).Before(now) {
			continue
		}

		msg := ""
		msgLevel := &results.Errors
		switch notif.Type_ {
		case "CorpNoLongerWarEligible":
			if app.config.Checks[CheckNotifs][NotifWarStatus] {
				msg = "No longer war eligible"
				msgLevel = &results.Info
			}
		case "CorpBecameWarEligible":
			if app.config.Checks[CheckNotifs][NotifWarStatus] {
				msg = "Became war eligible"
			}
		case "StructureAnchoring":
			if app.config.Checks[CheckNotifs][NotifAnchoring] {
				msg = "Has a structure anchoring"
			}
		case "StructureOnline":
			if app.config.Checks[CheckNotifs][NotifOnlining] {
				msg = "Has onlined a structure"
			}
		}

		if msg != "" {
			msg = fmt.Sprintf("%s at %s", msg, notif.Timestamp.Format(dateTimeFormat))
			*msgLevel = append(*msgLevel, msg)
		}
	}

	log.Printf("Parsed CEO's notifications after %f ceoID=%d corpID=%d", time.Since(startTime).Seconds(), corpData.CeoId, corpID)
}

func (app *app) discoverNaughtyMembers(corpID int32, corpData *esi.GetCorporationsCorporationIdOk, results *corpVerificationResult, charIgnoreList []int32, startTime time.Time) {
	const defaultChunkSize = 30

	// Get member list from ESI - datasource changes based on what corp you're querying, use the CEO's charID.
	ceoStringID := optional.NewString(results.Ceo.Name)
	corpMembersOpts := &esi.GetCorporationsCorporationIdMembersOpts{Datasource: ceoStringID}
	esiCorpMembers, response, err := app.proxyEsi.ESI.CorporationApi.GetCorporationsCorporationIdMembers(app.proxyAuthContext, corpID, corpMembersOpts)
	if err != nil {
		logline := "Proxy: Error getting characters for corp from esi."
		if response == nil {
			logline = logline + fmt.Sprintf(" (Invalid CEO Token?) corpID=%d httpResponse=nil error=\"%s\"", corpID, err.Error())
			results.Errors = append(results.Errors, logline)
			log.Print(logline)
			return
		}
		logline = logline + fmt.Sprintf(" corpID=%d status=\"%s\" error=\"%s\"", corpID, response.Status, err.Error())
		log.Print(logline)

		switch response.StatusCode {
		default:
			results.Errors = append(results.Errors, logline)
		case http.StatusForbidden:
			results.Errors = append(results.Errors, "Re-auth corp CEO: Needs ESI scope for member list.")
		}

		return
	}
	log.Printf("ESI Corp Members retrieved after %f corpID=%d", time.Since(startTime).Seconds(), corpID)

	// Get member list from Neucore
	neuCorpMembers, _, err := app.neu.ApplicationCharactersApi.CharacterListV1(app.neucoreContext).RequestBody(esiCorpMembers).Execute()
	if err != nil {
		log.Printf("Neu: Error getting characters for corp from neucore. corpID=%d error=\"%s\"", corpID, corpData.Name)
		results.Errors = append(results.Errors, fmt.Sprintf("Error getting characters from Neucore. error=\"%s\"", err.Error()))
		return
	}
	log.Printf("Neucore Corp Members retrieved after %f corpID=%d", time.Since(startTime).Seconds(), corpID)

	///////////////////

	// Determine if a character is missing or has an invalid token in neucore.
	var missingMembers []int32
	var invalidMembers []int32
	for _, charID := range esiCorpMembers {
		if app.config.Checks[CheckChars][CharsExist] &&
			!slices.ContainsFunc[neucoreapi.Character](neuCorpMembers, func(c neucoreapi.Character) bool {
				return c.GetId() == int64(charID)
			}) {
			// missing character
			if slices.Contains(charIgnoreList, charID) {
				log.Printf("Ignored Character missing from neucore id=%d", charID)
				continue
			}
			missingMembers = append(missingMembers, charID)
		} else {
			if app.config.Checks[CheckChars][CharsValid] &&
				!slices.ContainsFunc[neucoreapi.Character](neuCorpMembers, func(c neucoreapi.Character) bool {
					return c.GetId() == int64(charID)
				}) {
				// invalid token
				if slices.Contains(charIgnoreList, charID) {
					log.Printf("Ignored Character with invalid neucore token id=%d", charID)
					continue
				}
				invalidMembers = append(invalidMembers, charID)
			}
		}
	}

	// Get missing and invalid member names from ESI
	var invalidMemberStrings []string
	var missingMemberStrings []string
	numMissingMembers := len(missingMembers)
	numInvalidMembers := len(invalidMembers)
	naughtyIDs := append(missingMembers, invalidMembers...)
	missingMemberStrings, invalidMemberStrings, err = app.chunkNameRequest(naughtyIDs, missingMembers, invalidMembers)
	if err != nil {
		log.Printf("%s", err.Error())
	}

	////////////////////

	// Check for characters in Neucore, but lacking 'member' group (no chars in brave proper, or gone inactive)
	var charsMissingGroup []int32
	var namesMissingGroup []string
	if app.config.Checks[CheckChars][CharsMember] {
		characterGroups, _, err := app.neu.ApplicationGroupsApi.GroupsBulkV1(app.neucoreContext).RequestBody(esiCorpMembers).Execute()
		if err != nil {
			log.Printf("Neu: Error retreiving bulk character groups error=\"%s\"", err.Error())
		}

		for _, char := range characterGroups {
			charID := int32(char.Character.GetId())
			if slices.Contains(charIgnoreList, charID) {
				continue
			}
			if slices.Contains(naughtyIDs, charID) {
				continue
			}

			if !slices.ContainsFunc[neucoreapi.Group](char.Groups, func(g neucoreapi.Group) bool {
				return g.GetName() == "member"
			}) {
				// check for invalid token on other characters.
				playerChars, _, err := app.neu.ApplicationCharactersApi.CharactersV1(app.neucoreContext, charID).Execute()
				if err != nil {
					c := char.GetCharacter()
					message := fmt.Sprintf("Error retrieving alts. character=%d error=\"%s\"", c.GetId(), err.Error())
					results.Warnings = append(results.Warnings, message)
					log.Print(message)
				}

				hasCharWithInvalidToken := false
				for _, alt := range playerChars {
					if !alt.GetValidToken() {
						hasCharWithInvalidToken = true
						break
					}
				}

				if hasCharWithInvalidToken {
					invalidMembers = append(invalidMembers, charID)
					invalidMemberStrings = append(invalidMemberStrings, fmt.Sprintf("<https://evewho.com/character/%d|%s>'", charID, char.Character.Name))
					numInvalidMembers++
				} else {
					charsMissingGroup = append(charsMissingGroup, charID)
					namesMissingGroup = append(namesMissingGroup, char.Character.Name)
				}
			}
		}
	}

	var missingGroupMemberStrings []string
	numMembersMissingGroup := len(charsMissingGroup)
	if numMembersMissingGroup > 0 {
		chunkSize := min(defaultChunkSize, numMembersMissingGroup)
		chars := charsMissingGroup[:chunkSize]
		for i := range chars {
			missingGroupMemberStrings = append(missingGroupMemberStrings, fmt.Sprintf("<%s://%s/#UserAdmin/%d|%s>", app.config.NeucoreHTTPScheme, app.config.NeucoreDomain, charsMissingGroup[i], namesMissingGroup[i]))
		}

		if numMembersMissingGroup > chunkSize {
			missingGroupMemberStrings = append(missingGroupMemberStrings, fmt.Sprintf("and %d more...", numMembersMissingGroup-chunkSize))
		}
	}

	if numMissingMembers > 0 {
		missingChunkSize := min(defaultChunkSize, numMissingMembers)
		if len(missingMemberStrings) > missingChunkSize {
			missingMemberStrings = append(missingMemberStrings, fmt.Sprintf("and %d more...", numMissingMembers-missingChunkSize))
		}
		results.Errors = append(results.Errors, fmt.Sprintf(
			"Characters not in Neucore: %d\n%s",
			numMissingMembers,
			strings.Join(missingMemberStrings, ", ")))
	}

	if numInvalidMembers > 0 {
		invalidChunkSize := min(defaultChunkSize, numInvalidMembers)
		if len(invalidMemberStrings) > invalidChunkSize {
			invalidMemberStrings = append(invalidMemberStrings, fmt.Sprintf("and %d more...", numInvalidMembers-invalidChunkSize))
		}
		results.Errors = append(results.Errors, fmt.Sprintf(
			"Characters with invalid Neucore tokens: %d\n%s",
			numInvalidMembers,
			strings.Join(invalidMemberStrings, ", ")))
	}

	if numMembersMissingGroup > 0 {
		missingChunkSize := min(defaultChunkSize, numMembersMissingGroup)
		missingGroupMemberStrings = missingGroupMemberStrings[:missingChunkSize]
		results.Warnings = append(results.Warnings, fmt.Sprintf(
			"Characters without 'member' roles: %d\n%s",
			numMembersMissingGroup,
			strings.Join(missingGroupMemberStrings, ", ")))
	}

	log.Printf("Naughty list compiled after %f corpID=%d err/warn/info=%d/%d/%d missing=%d invalid=%d notMember=%d",
		time.Since(startTime).Seconds(),
		corpID,
		len(results.Errors),
		len(results.Warnings),
		len(results.Info),
		numMissingMembers,
		numInvalidMembers,
		numMembersMissingGroup)
}

func (app *app) esiHealthCheck() ([]string, error) {
	defer app.perfTime("esiHealthCheck", nil)
	var generalErrors []string
	var err error
	status, _, err := app.esi.Meta.MetaApi.GetStatus(context.Background(), nil)
	if err != nil {
		log.Printf("Error getting ESI Status error=\"%s\"", err.Error())
		generalErrors = append(generalErrors, "Error getting ESI Status")
		return generalErrors, err
	}

	for _, endpoint := range status {
		if endpoint.Status != "green" {
			usedEndpoint := endpoint.Route == "/alliances/{alliance_id}/corporations/" || // public,  corp list
				endpoint.Route == "/corporations/{corporation_id}/" || // public,  tax rate
				endpoint.Route == "/corporations/{corporation_id}/members/" || // private, character list
				endpoint.Route == "/characters/{character_id}/notifications/" // private, war and structure notifs

			if usedEndpoint {
				status := ":heart:"
				if endpoint.Status == "yellow" {
					status = ":yellow_heart:"
				}
				generalErrors = append(generalErrors, fmt.Sprintf("%s `%s`", status, endpoint.Route))
			}
		}
	}

	return generalErrors, err
}

func (app *app) chunkNameRequest(naughtyIDs []int32, missingMembers []int32, invalidMembers []int32) ([]string, []string, error) {
	const NAME_POST_LIMIT = 1000
	if len(naughtyIDs) <= 0 {
		return []string{}, []string{}, nil
	}

	var missingMemberStrings, invalidMemberStrings []string
	naughtyCount := len(naughtyIDs)
	for i := 0; i < len(naughtyIDs); i += NAME_POST_LIMIT {
		batchIDs := naughtyIDs[i:min(i+NAME_POST_LIMIT, naughtyCount)]
		naughtyNames, response, err := app.esi.ESI.UniverseApi.PostUniverseNames(context.TODO(), batchIDs, nil)
		if err != nil {
			return nil, nil, fmt.Errorf("error retreving bulk character names request=\"%v\" error=\"%s\"", naughtyIDs, err.Error())
		}
		if response.StatusCode != http.StatusOK {
			return nil, nil, fmt.Errorf("error retreving bulk character names request=\"%v\" status=%d", naughtyIDs, response.StatusCode)
		}

		for _, name := range naughtyNames {
			if name.Category != "character" {
				continue
			}

			if slices.Contains(missingMembers, name.Id) {
				missingMemberStrings = append(missingMemberStrings, fmt.Sprintf("<https://evewho.com/character/%d|%s>", name.Id, name.Name))
			} else {
				if slices.Contains(invalidMembers, name.Id) {
					invalidMemberStrings = append(invalidMemberStrings, fmt.Sprintf("<https://evewho.com/character/%d|%s>", name.Id, name.Name))
				}
			}
		}
	}

	return missingMemberStrings, invalidMemberStrings, nil
}
