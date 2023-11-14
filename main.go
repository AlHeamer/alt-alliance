package main

import (
	"context"
	"encoding/base64"
	"flag"
	"fmt"
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

const (
	DateTimeFormat = "2006-01-02 15:04"
	MaxRetryCount  = 5
)
const (
	// char data
	CheckCharsExist  = "CharacterExists"
	CheckCharsGroups = "CharacterGroups"
	CheckCharsValid  = "CharacterValidToken"
	// corp data
	CheckCorpTaxRate     = "CorpTaxRate"
	CheckCorpWarEligible = "CorpWarEligible"
	// ceo notifictaions
	CheckNotifAnchoring = "NotifStructureAnchoring"
	CheckNotifOnlining  = "NotifStructureOnlining"
	CheckNotifWarStatus = "NotifWarStatus"
)

var requiredRoles = [...]neucoreapi.Role{neucoreapi.APP, neucoreapi.APP_CHARS, neucoreapi.APP_ESI_PROXY, neucoreapi.APP_GROUPS}

func min[T ~int](a, b T) T {
	if a <= b {
		return a
	}
	return b
}

type config struct {
	NeucoreAppID            uint            `yaml:"NeucoreAppID"`
	Threads                 int             `yaml:"Threads" default:"20"`
	CorpBaseTaxRate         float32         `yaml:"CorpBaseTaxRate"`
	RequestTimeoutInSeconds uint            `yaml:"RequestTimeoutInSeconds" default:"120"`
	NeucoreHTTPScheme       string          `yaml:"NeucoreHTTPScheme" default:"http"`
	NeucoreDomain           string          `yaml:"NeucoreDomain"`
	NeucoreAppSecret        string          `yaml:"NeucoreAppSecret"`
	NeucoreUserAgent        string          `yaml:"NeucoreUserAgent"`
	NeucoreAPIBase          string          `yaml:"-"`
	EsiUserAgent            string          `yaml:"EsiUserAgent"`
	SlackWebhookURL         string          `yaml:"SlackWebhookURL"`
	CheckAlliances          []int32         `yaml:"CheckAlliances"`
	CheckCorps              []int32         `yaml:"CheckCorps"`
	IgnoreCorps             []int32         `yaml:"IgnoreCorps"`
	IgnoreChars             []int32         `yaml:"IgnoreChars"`
	Checks                  map[string]bool `yaml:"Checks"`
	RequiredGroups          []string        `yaml:"RequiredGroups"`
	Quiet                   bool            `yaml:"-"`
	DryRun                  bool            `yaml:"-"`
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

func (app *app) perfTime(msg string, t *time.Time, args ...any) {
	if t == nil {
		tt := time.Now()
		t = &tt
	}
	app.logger.Info(msg, slog.Duration("duration", time.Since(*t)), args)
}

func (app *app) initApp() error {
	defer app.perfTime("init complete", &app.startTime)
	opts := &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}
	app.logger = slog.New(slog.NewTextHandler(os.Stdout, opts))
	slog.SetDefault(app.logger)

	// read command line flags to get config file, then parse into app.config
	var configFile string
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage of %s:\n  unset checks using -flag=f\n\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.StringVar(&configFile, "f", "./config.yaml", "Config file to use")
	var notifWarEligible, notifStructure bool
	flag.BoolVar(&notifWarEligible, "notif-war", false, "Check CEO notifications for changes in war eligibility status")
	flag.BoolVar(&notifStructure, "notif-structure", false, "Check CEO notifications for anchoring or onlining structures")
	var corpTaxRate, corpWarEligible bool
	flag.BoolVar(&corpWarEligible, "corp-tax", false, "Check that corp tax rate matches that set in config")
	flag.BoolVar(&corpTaxRate, "corp-war", false, "Check that corps are not war eligible")
	var charExists, charValid, charGroups bool
	flag.BoolVar(&charExists, "char-exists", false, "Check that the character exists in neucore")
	flag.BoolVar(&charValid, "char-valid", false, "Check that all alts in neucore have a valid esi token")
	flag.BoolVar(&charGroups, "char-groups", false, "Check at least one character has each neucore role")
	var quiet, dryrun bool
	flag.BoolVar(&quiet, "q", false, "Don't print the execution time footer to slack if there are no issues")
	flag.BoolVar(&dryrun, "dry-run", false, "Don't output to slack")
	flag.BoolVar(&dryrun, "n", false, "alias of -dry-run")
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
	app.config.Quiet = quiet
	app.config.DryRun = dryrun

	// overwrite check flags with command line settings (if set)
	flag.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "notif-war":
			app.config.Checks[CheckNotifWarStatus] = notifWarEligible
		case "notif-structure":
			app.config.Checks[CheckNotifAnchoring] = notifStructure
			app.config.Checks[CheckNotifOnlining] = notifStructure
		case "corp-tax":
			app.config.Checks[CheckCorpTaxRate] = corpTaxRate
		case "corp-war":
			app.config.Checks[CheckCorpWarEligible] = corpWarEligible
		case "char-exists":
			app.config.Checks[CheckCharsExist] = charExists
		case "char-valid":
			app.config.Checks[CheckCharsValid] = charValid
		case "char-groups":
			app.config.Checks[CheckCharsGroups] = charGroups
		}
	})
	app.logger.Info("will perform the following",
		slog.Any("alliances", app.config.CheckAlliances),
		slog.Any("corporations", app.config.CheckCorps),
		slog.Any("ignored_corps", app.config.IgnoreCorps),
		slog.Any("ignored_chars", app.config.IgnoreChars),
		slog.Any("checks", app.config.Checks))

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

	t, err := neucoreTokenSource.Token()
	if err != nil {
		app.logger.Error("error getting token from token source", slog.Any("error", err))
		return err
	}
	app.neucoreContext = context.WithValue(context.Background(), neucoreapi.ContextAccessToken, t.AccessToken)
	return nil
}

func main() {
	app := app{
		startTime: time.Now(),
	}
	defer app.perfTime("completed execution", &app.startTime)

	// load config
	if err := app.initApp(); err != nil {
		return
	}

	// Perform ESI Health check.
	var blocks []slack.Block
	var generalErrors []string
	var healthErrs []string
	var err error
	healthErrs, err = app.esiHealthCheck()
	generalErrors = append(generalErrors, healthErrs...)
	if err != nil {
		app.generateAndSendWebhook(generalErrors, blocks)
		return
	}

	// Neucore Roles Check
	var rolesErrs []string
	rolesErrs, err = app.neucoreRolesCheck()
	generalErrors = append(generalErrors, rolesErrs...)
	if err != nil {
		app.generateAndSendWebhook(generalErrors, blocks)
		return
	}

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
					app.logger.Error("ESI: Error getting alliance corp list", slog.Int64("allianceID", int64(allianceID)), slog.Any("error", err))
					// dump and exit
					logline := fmt.Sprintf(`ESI: Error getting alliance corp list for allianceID=%d error="%s"`, allianceID, err.Error())
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

	financeTokens := make(map[int32]bool)
	if app.config.Checks[CheckCorpTaxRate] {
		wg.Add(1)
		go func() {
			defer wg.Done()
			neucoreTokenData, resp, err := app.neu.ApplicationESIApi.EsiEveLoginTokenDataV1(app.neucoreContext, "finance").Execute()
			if err != nil || resp.StatusCode != http.StatusOK {
				eString := "nil"
				if err != nil {
					eString = err.Error()
				}
				app.logger.Error("neucore: error getting finance token data", slog.Int("statuscode", resp.StatusCode), slog.Any("error", err))
				generalErrors = append(generalErrors, fmt.Sprintf("Neucore: Error getting finance token data statusCode=%d error=%s", resp.StatusCode, eString))
			}
			for _, v := range neucoreTokenData {
				financeTokens[v.GetCorporationId()] = true
			}
			delete(financeTokens, 0)
		}()
	}

	wg.Wait()

	// check each corp in the alliance
	queueLength := len(allCorps)
	queue = make(chan int32, queueLength)
	for i := 0; i < app.config.Threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for corpID := range queue {
				if slices.Contains(app.config.IgnoreCorps, corpID) {
					app.logger.Info("ignored corporation", slog.Int("id", int(corpID)))
					continue
				}

				corpResult := app.verifyCorporation(corpID, app.config.IgnoreChars)

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

	app.generateAndSendWebhook(generalErrors, blocks)
}

func (app *app) verifyCorporation(corpID int32, charIgnoreList []int32) *corpVerificationResult {
	defer app.perfTime("verify corporation completed", nil, slog.Int("corpID", int(corpID)))
	l := app.logger.With(slog.Int("corpID", int(corpID)))
	results := &corpVerificationResult{
		CorpID:   corpID,
		CorpName: fmt.Sprintf("Corp %d", corpID),
		Ceo:      &neucoreapi.Character{Name: "CEO"},
		CeoMain:  &neucoreapi.Character{Name: "???"},
	}

	// Get public corp data
	corpData, _, err := app.esi.ESI.CorporationApi.GetCorporationsCorporationId(context.TODO(), corpID, nil)
	if err != nil {
		l.Error("Error getting public corp info", slog.Any("error", err))
		results.Errors = append(results.Errors, "Error getting public corp info.")
		return results
	}
	results.CorpName = corpData.Name
	results.MemberCount = corpData.MemberCount
	ceoId := int64(corpData.CeoId)
	results.Ceo.Id = *neucoreapi.NewNullableInt64(&ceoId)
	results.Ceo.Name = fmt.Sprintf("%d", corpData.CeoId)

	// Get CEO info from neucore
	neuMain, response, err := app.neu.ApplicationCharactersApi.MainV2(app.neucoreContext, corpData.CeoId).Execute()
	if err != nil {
		var status string
		if response != nil {
			status = response.Status
		}
		l.Error("Neu: error retreiving CEO's main", slog.Int64("ceoID", ceoId), slog.String("status", status), slog.Any("error", err))
		logline := "Neu: Error retreiving CEO's main."
		if response == nil {
			logline = logline + fmt.Sprintf(` ceoID=%d corpID=%d httpResponse=nil error="%s"`, corpID, corpData.CeoId, err.Error())
			results.Errors = append(results.Errors, logline)
			return results
		}
		//logline = logline + fmt.Sprintf(` ceoID=%d corpID=%d status="%s" error="%s"`, corpID, corpData.CeoId, response.Status, err.Error())

		switch response.StatusCode {
		default:
			//results.Errors = append(results.Errors, logline)
		case http.StatusNotFound:
			results.Errors = append(results.Errors, "CEO or CEO's main not found in Neucore.")
		}
		return results
	}
	results.CeoMain = neuMain

	///
	/// Check CEO's notifications (cached 10 minutes)
	///
	app.checkCeoNotifications(corpID, &corpData, results)

	///
	/// Check corp info and member lists (cached 1 hour)
	///
	if app.config.Checks[CheckCorpTaxRate] && corpData.TaxRate < app.config.CorpBaseTaxRate {
		results.Errors = append(results.Errors, fmt.Sprintf("Tax rate is %.f%% (expected at least %.f%%)", corpData.TaxRate*100, app.config.CorpBaseTaxRate*100))
	}
	if app.config.Checks[CheckCorpWarEligible] && corpData.WarEligible {
		results.Errors = append(results.Errors, "Corporation is War Eligible.")
	}
	app.discoverNaughtyMembers(corpID, &corpData, results, charIgnoreList)

	return results
}

func (app *app) checkCeoNotifications(corpID int32, corpData *esi.GetCorporationsCorporationIdOk, results *corpVerificationResult) {
	defer app.perfTime("check ceo notifications", nil, slog.Int("corpID", int(corpID)))
	l := app.logger.With(slog.Int("corpID", int(corpID)), slog.Int("ceoID", int(corpData.CeoId)))
	if !app.config.Checks[CheckNotifAnchoring] && !app.config.Checks[CheckNotifOnlining] && !app.config.Checks[CheckNotifWarStatus] {
		app.logger.Info("no checks for notifications")
		return
	}
	ceoStringID := optional.NewString(results.Ceo.Name)
	notificationOpts := &esi.GetCharactersCharacterIdNotificationsOpts{Datasource: ceoStringID}
	notifications, response, err := app.proxyEsi.ESI.CharacterApi.GetCharactersCharacterIdNotifications(app.proxyAuthContext, corpData.CeoId, notificationOpts)
	if err != nil {
		logline := "Proxy: Error getting CEO's notifications."
		l.Error(logline, slog.Any("response", response), slog.Any("error", err))
		if response == nil {
			logline = logline + fmt.Sprintf(` httpResponse=nil error="%s"`, err.Error())
			results.Errors = append(results.Errors, logline)
			return
		}
		//logline = logline + fmt.Sprintf(` status="%s" error="%s"`, response.Status, err.Error())

		switch response.StatusCode {
		default:
			//results.Errors = append(results.Errors, logline)
		case http.StatusForbidden:
			results.Errors = append(results.Errors, "Re-auth corp CEO: Needs ESI scope for notifications.")
		}
	}

	for _, notif := range notifications {
		if notif.Timestamp.Add(time.Hour).Before(time.Now().UTC()) {
			continue
		}

		msg := ""
		msgLevel := &results.Errors
		switch notif.Type_ {
		case "CorpNoLongerWarEligible":
			if app.config.Checks[CheckNotifWarStatus] {
				msg = "No longer war eligible"
				msgLevel = &results.Info
			}
		case "CorpBecameWarEligible":
			if app.config.Checks[CheckNotifWarStatus] {
				msg = "Became war eligible"
			}
		case "StructureAnchoring":
			if app.config.Checks[CheckNotifAnchoring] {
				msg = "Has a structure anchoring"
			}
		case "StructureOnline":
			if app.config.Checks[CheckNotifOnlining] {
				msg = "Has onlined a structure"
			}
		}

		if msg != "" {
			msg = fmt.Sprintf("%s at %s", msg, notif.Timestamp.Format(DateTimeFormat))
			*msgLevel = append(*msgLevel, msg)
		}
	}
}

func (app *app) discoverNaughtyMembers(corpID int32, corpData *esi.GetCorporationsCorporationIdOk, results *corpVerificationResult, charIgnoreList []int32) {
	defer app.perfTime("discovered naughty members", nil, slog.Int("corpID", int(corpID)))
	l := app.logger.With(slog.Int("corpID", int(corpID)))
	if !app.config.Checks[CheckCharsExist] && !app.config.Checks[CheckCharsValid] && !app.config.Checks[CheckCharsGroups] {
		l.Info("no character checks to perform")
		return
	}
	const defaultChunkSize = 30

	// Get member list from ESI - datasource changes based on what corp you're querying, use the CEO's charID.
	ceoStringID := optional.NewString(results.Ceo.Name)
	corpMembersOpts := &esi.GetCorporationsCorporationIdMembersOpts{Datasource: ceoStringID}
	esiCorpMembers, response, err := app.proxyEsi.ESI.CorporationApi.GetCorporationsCorporationIdMembers(app.proxyAuthContext, corpID, corpMembersOpts)
	if err != nil {
		logline := "Proxy: Error getting characters for corp from esi."
		l.Error(logline, slog.Any("response", response), slog.Any("error", err))
		if response == nil {
			logline = logline + fmt.Sprintf(` (Invalid CEO Token?) corpID=%d httpResponse=nil error="%s"`, corpID, err.Error())
			results.Errors = append(results.Errors, logline)
			return
		}
		//logline = logline + fmt.Sprintf(` corpID=%d status="%s" error="%s"`, corpID, response.Status, err.Error())

		switch response.StatusCode {
		default:
			//results.Errors = append(results.Errors, logline)
		case http.StatusForbidden:
			results.Errors = append(results.Errors, "Re-auth corp CEO: Needs ESI scope for member list.")
		}

		return
	}

	// Get member list from Neucore
	neuCorpMembers, _, err := app.neu.ApplicationCharactersApi.CharacterListV1(app.neucoreContext).RequestBody(esiCorpMembers).Execute()
	if err != nil {
		l.Error("Neu: Error getting characters for corp from neucore", slog.Any("error", err))
		results.Errors = append(results.Errors, fmt.Sprintf(`Error getting characters from Neucore. error="%s"`, err.Error()))
		return
	}

	///////////////////

	// Determine if a character is missing or has an invalid token in neucore.
	var missingMembers []int32
	var invalidMembers []int32
	if app.config.Checks[CheckCharsExist] || app.config.Checks[CheckCharsValid] {
		for _, charID := range esiCorpMembers {
			if slices.Contains(charIgnoreList, charID) {
				l.Info("Ignored Character")
				continue
			}
			if app.config.Checks[CheckCharsExist] &&
				!slices.ContainsFunc(neuCorpMembers, func(c neucoreapi.Character) bool {
					return c.GetId() == int64(charID)
				}) {
				// missing character
				missingMembers = append(missingMembers, charID)
			} else {
				if app.config.Checks[CheckCharsValid] &&
					!slices.ContainsFunc(neuCorpMembers, func(c neucoreapi.Character) bool {
						return c.GetId() == int64(charID)
					}) {
					// invalid token
					invalidMembers = append(invalidMembers, charID)
				}
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
		l.Error("error getting names from ids", slog.Any("error", err))
	}

	////////////////////

	// Check for characters in Neucore, but lacking 'member' group (no chars in brave proper, or gone inactive)
	var charsMissingGroup []int32
	var namesMissingGroup []string
	if app.config.Checks[CheckCharsGroups] {
		characterGroups, _, err := app.neu.ApplicationGroupsApi.GroupsBulkV1(app.neucoreContext).RequestBody(esiCorpMembers).Execute()
		if err != nil {
			l.Error("Neu: Error retreiving bulk character groups", slog.Any("error", err))
		}

		for _, char := range characterGroups {
			charID := int32(char.Character.GetId())
			if slices.Contains(charIgnoreList, charID) {
				continue
			}
			if slices.Contains(naughtyIDs, charID) {
				continue
			}
			log := l.With(slog.Int("charID", int(charID)))

			if !slices.ContainsFunc(char.Groups, func(g neucoreapi.Group) bool {
				return slices.Contains(app.config.RequiredGroups, g.GetName())
			}) {
				// check for invalid token on other characters.
				playerChars, _, err := app.neu.ApplicationCharactersApi.CharactersV1(app.neucoreContext, charID).Execute()
				if err != nil {
					c := char.GetCharacter()
					message := fmt.Sprintf(`Error retrieving alts. character=%d error="%s"`, c.GetId(), err.Error())
					results.Warnings = append(results.Warnings, message)
					log.Error("error retrieving alts", slog.Int("character", int(c.GetId())), slog.Any("error", err))
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
			"Characters missing required role(s): %d\n%s",
			numMembersMissingGroup,
			strings.Join(missingGroupMemberStrings, ", ")))
	}

	l.Info("naughty list compiled",
		slog.Int("errors", len(results.Errors)),
		slog.Int("warnings", len(results.Warnings)),
		slog.Int("infos", len(results.Info)),
		slog.Int("missing", numMissingMembers),
		slog.Int("invalid", numInvalidMembers),
		slog.Int("non-member", numMembersMissingGroup))
}

func (app *app) esiHealthCheck() ([]string, error) {
	defer app.perfTime("esiHealthCheck", nil)
	var generalErrors []string
	var err error
	status, _, err := app.esi.Meta.MetaApi.GetStatus(context.Background(), nil)
	if err != nil {
		app.logger.Error("Error getting ESI Status", slog.Any("error", err))
		generalErrors = append(generalErrors, "Error getting ESI Status")
		return generalErrors, err
	}

	for _, endpoint := range status {
		if endpoint.Status != "green" {
			usedEndpoint := endpoint.Route == "/alliances/{alliance_id}/corporations/" || // public, corp list
				endpoint.Route == "/corporations/{corporation_id}/" || // public, tax rate
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

	return generalErrors, nil
}

func (app *app) neucoreRolesCheck() ([]string, error) {
	defer app.perfTime("neucoreRolesCheck", nil)
	var generalErrors []string
	neucoreAppData, _, err := app.neu.ApplicationApi.ShowV1(app.neucoreContext).Execute()
	if err != nil {
		neucoreError := fmt.Sprintf(`Error checking neucore app info. error="%s"`, err.Error())
		app.logger.Error("error checking neucore app info", slog.Any("error", err))
		generalErrors = append(generalErrors, neucoreError)
		return generalErrors, err
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
			app.logger.Error("neucore config error - missing roles", slog.Any("given", neucoreAppData.Roles), slog.Any("required", requiredRoles))
			generalErrors = append(generalErrors, msg)
			return generalErrors, fmt.Errorf("app missing required neucore roles")
		}
	}
	return nil, nil
}

func (app *app) chunkNameRequest(naughtyIDs []int32, missingMembers []int32, invalidMembers []int32) ([]string, []string, error) {
	defer app.perfTime("chunk name request", nil)
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
			return nil, nil, fmt.Errorf(`error retreving bulk character names request="%v" error="%s"`, naughtyIDs, err.Error())
		}
		if response.StatusCode != http.StatusOK {
			return nil, nil, fmt.Errorf(`error retreving bulk character names request="%v" status=%d`, naughtyIDs, response.StatusCode)
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
