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

func min[T ~int](a, b T) T {
	if a <= b {
		return a
	}
	return b
}

type app struct {
	Config           config
	ESI              *goesi.APIClient
	ProxyESI         *goesi.APIClient
	Neu              *neucoreapi.APIClient
	NeucoreContext   context.Context
	ProxyAuthContext context.Context
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

var requiredRoles = [...]neucoreapi.Role{neucoreapi.APP, neucoreapi.APP_CHARS, neucoreapi.APP_ESI, neucoreapi.APP_GROUPS}

const dateTimeFormat = "2006-01-02 15:04"

func (app *app) readFlags(l *slog.Logger) error {
	var configFile string
	flag.StringVar(&configFile, "f", "./config.yaml", "Config file to use")
	flag.Parse()

	var data []byte
	var err error
	if data, err = os.ReadFile(configFile); err != nil {
		l.Error("error reading config file", slog.String("configFile", configFile), slog.Any("error", err))
		return err
	}
	if err = yaml.Unmarshal(data, &app.Config); err != nil {
		l.Error("error parsing config file", slog.String("configFile", configFile), slog.Any("error", err))
		return err
	}

	l.Info("will perform the following", slog.Any("checks", app.Config.Checks))
	return nil
}

func (app *app) initApp() {
	// Init ESI
	httpc := &http.Client{Timeout: time.Second * time.Duration(app.Config.RequestTimeoutInSeconds)}
	app.ESI = goesi.NewAPIClient(httpc, app.Config.EsiUserAgent)

	// Init Neucore ESI Proxy
	app.ProxyESI = goesi.NewAPIClient(httpc, app.Config.NeucoreUserAgent)
	app.ProxyESI.ChangeBasePath(app.Config.NeucoreAPIBase + "/app/v2/esi")
	proxyAuth := goesi.NewSSOAuthenticatorV2(httpc, "", "", "", []string{})
	proxyToken := &oauth2.Token{
		AccessToken: base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%d:%s", app.Config.NeucoreAppID, app.Config.NeucoreAppSecret))),
		TokenType:   "bearer",
	}
	neucoreTokenSource := proxyAuth.TokenSource(proxyToken)
	app.ProxyAuthContext = context.WithValue(context.Background(), goesi.ContextOAuth2, neucoreTokenSource)

	// Init Neucore API
	neucoreConfig := &neucoreapi.Configuration{
		HTTPClient: httpc,
		UserAgent:  app.Config.NeucoreUserAgent,
		Servers: neucoreapi.ServerConfigurations{{
			URL:         app.Config.NeucoreAPIBase,
			Description: "Neucore API Base",
		}},
		OperationServers: map[string]neucoreapi.ServerConfigurations{},
	}

	app.Neu = neucoreapi.NewAPIClient(neucoreConfig)
	app.NeucoreContext = context.WithValue(context.Background(), neucoreapi.ContextOAuth2, neucoreTokenSource)
}

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	slog.SetDefault(logger)
	logger.Info("starting process...")
	startTime := time.Now()

	// load config
	var app app
	if err := app.readFlags(logger); err != nil {
		os.Exit(1)
	}

	app.Config.NeucoreAPIBase = fmt.Sprintf("%s://%s/api", app.Config.NeucoreHTTPScheme, app.Config.NeucoreDomain)

	// Init ESI, Neucore
	app.initApp()
	logger.Info("init complete", slog.Duration("duration", time.Since(startTime)))

	// Perform ESI Health check.
	var blocks []slack.Block
	generalErrors, err := app.esiHealthCheck()
	if err != nil {
		app.generateAndSendWebhook(startTime, generalErrors, &blocks)
		return
	}

	// Neucore Roles Check
	neucoreAppData, _, err := app.Neu.ApplicationApi.ShowV1(app.NeucoreContext).Execute()
	if err != nil {
		neucoreError := fmt.Sprintf("Error checking neucore app info. error=\"%s\"", err.Error())
		log.Print(neucoreError)
		generalErrors = append(generalErrors, neucoreError)
		app.generateAndSendWebhook(startTime, generalErrors, &blocks)
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
			app.generateAndSendWebhook(startTime, generalErrors, &blocks)
			return
		}
	}
	log.Printf("API Check Complete: %f", time.Since(startTime).Seconds())

	// Compile a list of all corps to check
	var allCorps []int32
	allCorps = append(allCorps, app.Config.CheckCorps...)

	// Get alliance's corp list
	queue := make(chan int32, len(app.Config.CheckAlliances))
	mutex := &sync.Mutex{}
	wg := sync.WaitGroup{}
	for i := 0; i < app.Config.Threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for allianceID := range queue {
				allianceCorps, _, err := app.ESI.ESI.AllianceApi.GetAlliancesAllianceIdCorporations(context.TODO(), allianceID, nil)
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

	for _, v := range app.Config.CheckAlliances {
		queue <- v
	}
	close(queue)

	wg.Add(1)
	financeTokens := make(map[int32]bool)
	go func() {
		defer wg.Done()
		neucoreTokenData, resp, err := app.Neu.ApplicationESIApi.EsiEveLoginTokenDataV1(app.NeucoreContext, "finance").Execute()
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
	log.Printf("Alliance Check Complete: %f", time.Since(startTime).Seconds())

	// check each corp in the alliance
	queueLength := len(allCorps)
	queue = make(chan int32, queueLength)
	var totalOwed float64
	for i := 0; i < app.Config.Threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for corpID := range queue {
				if slices.Contains(app.Config.IgnoreCorps, corpID) {
					log.Printf("Ignored Corporation id=%d", corpID)
					continue
				}

				corpResult := app.verifyCorporation(corpID, app.Config.IgnoreChars, startTime)

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
	if totalOwed > 2000000000 {
		generalErrors = append(generalErrors, fmt.Sprintf("Total corp taxes owed=%.f", totalOwed))
	}
	log.Printf("Corp Check Complete: %f", time.Since(startTime).Seconds())

	app.generateAndSendWebhook(startTime, generalErrors, &blocks)
}

func (app *app) verifyCorporation(corpID int32, charIgnoreList []int32, startTime time.Time) corpVerificationResult {
	now := time.Now()
	results := corpVerificationResult{
		CorpID:   corpID,
		CorpName: fmt.Sprintf("Corp %d", corpID),
		Ceo:      &neucoreapi.Character{Name: "CEO"},
		CeoMain:  &neucoreapi.Character{Name: "???"},
	}

	// Get public corp data
	corpData, _, err := app.ESI.ESI.CorporationApi.GetCorporationsCorporationId(context.TODO(), corpID, nil)
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
	neuMain, response, err := app.Neu.ApplicationCharactersApi.MainV2(app.NeucoreContext, corpData.CeoId).Execute()
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
	if len(app.Config.Checks[CheckCorps]) > 0 {
		app.checkCeoNotifications(corpID, &corpData, &results, now, startTime)
	}

	///
	/// Check corp info and member lists (cached 1 hour)
	///
	if app.Config.Checks[CheckCorps][CorpTaxRate] && corpData.TaxRate < app.Config.CorpBaseTaxRate {
		results.Errors = append(results.Errors, fmt.Sprintf("Tax rate is %.f%% (expected at least %.f%%)", corpData.TaxRate*100, app.Config.CorpBaseTaxRate*100))
	}
	if app.Config.Checks[CheckCorps][CorpWarEligible] && corpData.WarEligible {
		results.Errors = append(results.Errors, "Corporation is War Eligible.")
	}
	if len(app.Config.Checks[CheckChars]) > 0 {
		app.discoverNaughtyMembers(corpID, &corpData, &results, charIgnoreList, startTime)
	}

	return results
}

func (app *app) checkCeoNotifications(corpID int32, corpData *esi.GetCorporationsCorporationIdOk, results *corpVerificationResult, now time.Time, startTime time.Time) {
	ceoStringID := optional.NewString(results.Ceo.Name)
	notificationOps := &esi.GetCharactersCharacterIdNotificationsOpts{Datasource: ceoStringID}
	notifications, response, err := app.ProxyESI.ESI.CharacterApi.GetCharactersCharacterIdNotifications(app.ProxyAuthContext, corpData.CeoId, notificationOps)
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
			if app.Config.Checks[CheckNotifs][NotifWarStatus] {
				msg = "No longer war eligible"
				msgLevel = &results.Info
			}
		case "CorpBecameWarEligible":
			if app.Config.Checks[CheckNotifs][NotifWarStatus] {
				msg = "Became war eligible"
			}
		case "StructureAnchoring":
			if app.Config.Checks[CheckNotifs][NotifAnchoring] {
				msg = "Has a structure anchoring"
			}
		case "StructureOnline":
			if app.Config.Checks[CheckNotifs][NotifOnlining] {
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
	esiCorpMembers, response, err := app.ProxyESI.ESI.CorporationApi.GetCorporationsCorporationIdMembers(app.ProxyAuthContext, corpID, corpMembersOpts)
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
	neuCorpMembers, _, err := app.Neu.ApplicationCharactersApi.CharacterListV1(app.NeucoreContext).RequestBody(esiCorpMembers).Execute()
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
		if app.Config.Checks[CheckChars][CharsExist] &&
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
			if app.Config.Checks[CheckChars][CharsValid] &&
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
	if app.Config.Checks[CheckChars][CharsMember] {
		characterGroups, _, err := app.Neu.ApplicationGroupsApi.GroupsBulkV1(app.NeucoreContext).RequestBody(esiCorpMembers).Execute()
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
				playerChars, _, err := app.Neu.ApplicationCharactersApi.CharactersV1(app.NeucoreContext, charID).Execute()
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
			missingGroupMemberStrings = append(missingGroupMemberStrings, fmt.Sprintf("<%s://%s/#UserAdmin/%d|%s>", app.Config.NeucoreHTTPScheme, app.Config.NeucoreDomain, charsMissingGroup[i], namesMissingGroup[i]))
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
	generalErrors := []string{}
	var err error
	status, _, err := app.ESI.Meta.MetaApi.GetStatus(context.TODO(), nil)
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
		naughtyNames, response, err := app.ESI.ESI.UniverseApi.PostUniverseNames(context.TODO(), batchIDs, nil)
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
