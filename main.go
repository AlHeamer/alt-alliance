package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/antihax/goesi"
	"github.com/antihax/goesi/esi"
	"github.com/antihax/goesi/optional"
	neucoreapi "github.com/bravecollective/neucore-api-go"
	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/mysql"
	"github.com/slack-go/slack"
	"golang.org/x/oauth2"
)

type config struct {
	NeucoreAppID            uint
	Threads                 int `gorm:"default:20"`
	CorpBaseTaxRate         float32
	RequestTimeoutInSeconds int64  `gorm:"default:120"`
	NeucoreHTTPScheme       string `gorm:"default:'http'"`
	NeucoreDomain           string
	NeucoreAppSecret        string
	NeucoreUserAgent        string
	NeucoreAPIBase          string
	EsiUserAgent            string
	SlackWebhookURL         string
}

type CorpCheck int

const (
	// ceo notifictaions
	NOTIF_WAR_ELIGIBLE_CHANGED CorpCheck = 1 << iota // No longer war eligible or newly war eligible
	NOTIF_STRUCTURE_ANCHORING
	NOTIF_STRUCTURE_ONLINE
	// general corp info
	CORP_TAX_RATE
	CORP_WAR_ELIGIBLE
	// naughty character checks
	CHAR_EXISTS_IN_NEUCORE
	CHAR_VALID_NEUCORE_TOKEN
	CHAR_HAS_MEMBER_ROLE
)
const (
	CORP_CHECK_MASK_ALL   CorpCheck = -1
	CORP_CHECK_MASK_NONE  CorpCheck = 0
	CORP_CHECK_MASK_NOTIF CorpCheck = 0b000000111
	CORP_CHECK_MASK_CORP  CorpCheck = 0b000111000
	CORP_CHECK_MASK_CHAR  CorpCheck = 0b111000000
)

func (lhs CorpCheck) Check(rhs CorpCheck) bool {
	return lhs&rhs == rhs
}
func (lhs CorpCheck) CheckAny(rhs CorpCheck) bool {
	return lhs&rhs > 0
}
func (lhs CorpCheck) Set(rhs CorpCheck) CorpCheck {
	return lhs | rhs
}
func (lhs CorpCheck) Unset(rhs CorpCheck) CorpCheck {
	return lhs &^ rhs
}
func (lhs CorpCheck) CSet(rhs CorpCheck, set bool) CorpCheck {
	if set {
		return lhs.Set(rhs)
	}
	return lhs
}

type app struct {
	Config           config
	DB               *gorm.DB
	ESI              *goesi.APIClient
	ProxyESI         *goesi.APIClient
	Neu              *neucoreapi.APIClient
	NeucoreContext   context.Context
	ProxyAuthContext context.Context
	Checks           CorpCheck
}

type checkedAlliance struct {
	gorm.Model
	AllianceID int32
}

type checkedCorp struct {
	gorm.Model
	CorpID int32
}

type ignoredCorp struct {
	gorm.Model
	CorpID int32
	Reason string
}

type ignoredCharacter struct {
	gorm.Model
	CharacterID int32
	Reason      string
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

const dateFormat = "2006-01-02"
const dateTimeFormat = "2006-01-02 15:04"

func (app *app) initDB() {
	var err error

	// Setup DB
	user := "root"
	password := ""
	host := "/tmp/mysql.sock"
	dbName := "alt_alliance"
	sqlString := "%s:%s@tcp(%s)/%s?charset=utf8&parseTime=True&loc=Local"
	if u := os.Getenv("DB_USER"); u != "" {
		user = u
	}
	if p := os.Getenv("DB_PASS"); p != "" {
		password = p
	}
	if h := os.Getenv("DB_HOST"); h != "" {
		host = h
	}
	if n := os.Getenv("DB_NAME"); n != "" {
		dbName = n
	}

	flag.StringVar(&user, "u", user, "The username used to access the database. (env var DB_USER)")
	flag.StringVar(&password, "p", password, "The password for the user. (env var DB_PASS)")
	flag.StringVar(&host, "h", host, "The hostname of the database to connect to (can be a unix socket, ip address, or domain.) (env var DB_HOST)")
	flag.StringVar(&dbName, "d", dbName, "The name of the database to use. (env var DB_NAME)")
	var warStatus, structureAnchroing, structureOnline bool
	flag.BoolVar(&warStatus, "notif-war-status", true, "Check for changes in war eligibility status")
	flag.BoolVar(&structureAnchroing, "notif-structure-anchoring", true, "Check for anchoring structures")
	flag.BoolVar(&structureOnline, "notif-structure-online", true, "Check for onlining structures")
	var corpTaxRate, corpWarEligible bool
	flag.BoolVar(&corpTaxRate, "corp-tax-rate", true, "Check corporation tax rate is set correctly")
	flag.BoolVar(&corpWarEligible, "corp-war-eligible", true, "Check corporation war eligibility")
	var charExists, charValid, charMember bool
	flag.BoolVar(&charExists, "char-exists", true, "Check that characters exist in neucore")
	flag.BoolVar(&charValid, "char-valid-token", true, "Check that characters have a valid esi token in neucore")
	flag.BoolVar(&charMember, "char-member-role", true, "Check that characters have the 'member' role in neucore")
	flag.Parse()

	app.Checks = app.Checks.CSet(NOTIF_WAR_ELIGIBLE_CHANGED, warStatus)
	app.Checks = app.Checks.CSet(NOTIF_STRUCTURE_ANCHORING, structureAnchroing)
	app.Checks = app.Checks.CSet(NOTIF_STRUCTURE_ONLINE, structureOnline)
	app.Checks = app.Checks.CSet(CORP_TAX_RATE, corpTaxRate)
	app.Checks = app.Checks.CSet(CORP_WAR_ELIGIBLE, corpWarEligible)
	app.Checks = app.Checks.CSet(CHAR_EXISTS_IN_NEUCORE, charExists)
	app.Checks = app.Checks.CSet(CHAR_VALID_NEUCORE_TOKEN, charValid)
	app.Checks = app.Checks.CSet(CHAR_HAS_MEMBER_ROLE, charMember)
	log.Printf("will performing the following checks: 0b%s", strconv.FormatInt(int64(app.Checks), 2))

	if host[0:1] == "/" {
		sqlString = "%s:%s@unix(%s)/%s?charset=utf8&parseTime=True&loc=Local"
	}

	connArgs := fmt.Sprintf(sqlString, user, password, host, dbName)
	// Uncomment if you are trying to debug DB issues. Will reveal your password in logs.
	//log.Println(connArgs)
	app.DB, err = gorm.Open("mysql", connArgs)
	if err != nil {
		log.Fatal(err.Error(), "\n\nDB connection error: Did you forget to specify database params?")
	}

	app.DB.AutoMigrate(&config{})
	app.DB.AutoMigrate(&checkedAlliance{})
	app.DB.AutoMigrate(&checkedCorp{})
	app.DB.AutoMigrate(&ignoredCorp{})
	app.DB.AutoMigrate(&ignoredCharacter{})
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
	log.Printf("Starting process...")
	startTime := time.Now()

	// Init DB and load config
	var app app
	app.initDB()
	app.DB.First(&app.Config)
	app.Config.NeucoreAPIBase = fmt.Sprintf("%s://%s/api", app.Config.NeucoreHTTPScheme, app.Config.NeucoreDomain)

	// Init ESI, Neucore
	app.initApp()
	log.Printf("Init Complete: %f", time.Since(startTime).Seconds())

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
	var corpCheckList []checkedCorp
	app.DB.Select("corp_id").Find(&corpCheckList)
	for _, corp := range corpCheckList {
		allCorps = append(allCorps, corp.CorpID)
	}

	// Get alliance's corp list
	var allianceCheckList []checkedAlliance
	app.DB.Select("alliance_id").Find(&allianceCheckList)
	queueLength := len(allianceCheckList)
	queue := make(chan int32, queueLength)
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

	for i := 0; i < queueLength; i++ {
		queue <- allianceCheckList[i].AllianceID
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
		if _, ok := financeTokens[0]; ok {
			delete(financeTokens, 0)
		}
	}()

	wg.Wait()
	log.Printf("Alliance Check Complete: %f", time.Since(startTime).Seconds())

	// check each corp in the alliance
	queueLength = len(allCorps)
	queue = make(chan int32, queueLength)
	var corpIgnoreList []ignoredCorp
	var charIgnoreList []ignoredCharacter
	app.DB.Select("corp_id").Find(&corpIgnoreList)
	app.DB.Select("character_id").Find(&charIgnoreList)
	var totalOwed float64
	for i := 0; i < app.Config.Threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for corpID := range queue {
				if corpIsOnIgnoreList(corpID, &corpIgnoreList) {
					log.Printf("Ignored Corporation id=%d", corpID)
					continue
				}

				corpResult := app.verifyCorporation(corpID, charIgnoreList, startTime)

				if len(financeTokens) > 0 {
					if tok, ok := financeTokens[corpID]; !ok || (ok && tok == false) {
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

func (app *app) verifyCorporation(corpID int32, charIgnoreList []ignoredCharacter, startTime time.Time) corpVerificationResult {
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
	if app.Checks.CheckAny(CORP_CHECK_MASK_NOTIF) {
		app.checkCeoNotifications(corpID, &corpData, &results, now, startTime)
	}

	///
	/// Check corp info and member lists (cached 1 hour)
	///
	if app.Checks.Check(CORP_TAX_RATE) && corpData.TaxRate < app.Config.CorpBaseTaxRate {
		results.Errors = append(results.Errors, fmt.Sprintf("Tax rate is %.f%% (expected at least %.f%%)", corpData.TaxRate*100, app.Config.CorpBaseTaxRate*100))
	}
	if app.Checks.Check(CORP_WAR_ELIGIBLE) && corpData.WarEligible {
		results.Errors = append(results.Errors, "Corporation is War Eligible.")
	}
	if app.Checks.CheckAny(CORP_CHECK_MASK_CHAR) {
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
			if app.Checks.Check(NOTIF_WAR_ELIGIBLE_CHANGED) {
				msg = "No longer war eligible"
				msgLevel = &results.Info
			}
		case "CorpBecameWarEligible":
			if app.Checks.Check(NOTIF_WAR_ELIGIBLE_CHANGED) {
				msg = "Became war eligible"
			}
		case "StructureAnchoring":
			if app.Checks.Check(NOTIF_STRUCTURE_ANCHORING) {
				msg = "Has a structure anchoring"
			}
		case "StructureOnline":
			if app.Checks.Check(NOTIF_STRUCTURE_ONLINE) {
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

func (app *app) discoverNaughtyMembers(corpID int32, corpData *esi.GetCorporationsCorporationIdOk, results *corpVerificationResult, charIgnoreList []ignoredCharacter, startTime time.Time) {
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
		if app.Checks.Check(CHAR_EXISTS_IN_NEUCORE) &&
			!characterExistsInNeucore(int64(charID), neuCorpMembers) {
			// missing character
			if characterIsOnIgnoreList(charID, charIgnoreList) {
				log.Printf("Ignored Character missing from neucore id=%d", charID)
				continue
			}
			missingMembers = append(missingMembers, charID)
		} else {
			if app.Checks.Check(CHAR_VALID_NEUCORE_TOKEN) &&
				!characterHasValidNeucoreToken(int64(charID), neuCorpMembers) {
				// invalid token
				if characterIsOnIgnoreList(charID, charIgnoreList) {
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
	if app.Checks.Check(CHAR_HAS_MEMBER_ROLE) {
		characterGroups, _, err := app.Neu.ApplicationGroupsApi.GroupsBulkV1(app.NeucoreContext).RequestBody(esiCorpMembers).Execute()
		if err != nil {
			log.Printf("Neu: Error retreiving bulk character groups error=\"%s\"", err.Error())
		}

		for _, char := range characterGroups {
			charID := int32(char.Character.GetId())
			if characterIsOnIgnoreList(charID, charIgnoreList) {
				continue
			}
			if int32ExistsInArray(charID, &naughtyIDs) {
				continue
			}

			if !playerBelongsToGroup("member", char.Groups) {
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
		chunkSize := integerMin(defaultChunkSize, numMembersMissingGroup)
		chars := charsMissingGroup[:chunkSize]
		for i := range chars {
			missingGroupMemberStrings = append(missingGroupMemberStrings, fmt.Sprintf("<%s://%s/#UserAdmin/%d|%s>", app.Config.NeucoreHTTPScheme, app.Config.NeucoreDomain, charsMissingGroup[i], namesMissingGroup[i]))
		}

		if numMembersMissingGroup > chunkSize {
			missingGroupMemberStrings = append(missingGroupMemberStrings, fmt.Sprintf("and %d more...", numMembersMissingGroup-chunkSize))
		}
	}

	if numMissingMembers > 0 {
		missingChunkSize := integerMin(defaultChunkSize, numMissingMembers)
		if len(missingMemberStrings) > missingChunkSize {
			missingMemberStrings = append(missingMemberStrings, fmt.Sprintf("and %d more...", numMissingMembers-missingChunkSize))
		}
		results.Errors = append(results.Errors, fmt.Sprintf(
			"Characters not in Neucore: %d\n%s",
			numMissingMembers,
			strings.Join(missingMemberStrings, ", ")))
	}

	if numInvalidMembers > 0 {
		invalidChunkSize := integerMin(defaultChunkSize, numInvalidMembers)
		if len(invalidMemberStrings) > invalidChunkSize {
			invalidMemberStrings = append(invalidMemberStrings, fmt.Sprintf("and %d more...", numInvalidMembers-invalidChunkSize))
		}
		results.Errors = append(results.Errors, fmt.Sprintf(
			"Characters with invalid Neucore tokens: %d\n%s",
			numInvalidMembers,
			strings.Join(invalidMemberStrings, ", ")))
	}

	if numMembersMissingGroup > 0 {
		missingChunkSize := integerMin(defaultChunkSize, numMembersMissingGroup)
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

// 2022-09-13: Slack currently has a bug where it will resend messages n times where n = totalBlockTextLength / 4040
func getBlocksUpperBugged(blocks []slack.Block, lower int, upper int) int {
	var textLength int
	newUpper := lower
	for i := lower; i < upper; i++ {
		if blocks[i].BlockType() != slack.MBTSection {
			newUpper++
			continue
		}

		b := blocks[i].(*slack.SectionBlock)
		textLength += len(b.Text.Text)
		if textLength < 4040 {
			newUpper++
		} else {
			break
		}
	}
	return newUpper
}

func (app *app) generateAndSendWebhook(startTime time.Time, generalErrors []string, blocks *[]slack.Block) {
	generateStatusFooterBlock(startTime, generalErrors, blocks)

	// slack has a 50 block limit per message, and 1 message per second limit ("burstable.")
	const blocksPerMessage = 50
	blockArray := *blocks
	queuedBlocks := len(blockArray)
	var batchLen int
	for totalSentBlocks := 0; totalSentBlocks < queuedBlocks; totalSentBlocks += batchLen {
		upper := integerMin(totalSentBlocks+blocksPerMessage, queuedBlocks)
		upper = getBlocksUpperBugged(blockArray, totalSentBlocks, upper)
		batch := blockArray[totalSentBlocks:upper]
		batchLen = len(batch)

		m := slack.Blocks{BlockSet: batch}
		msg := &slack.WebhookMessage{
			Blocks: &m,
		}

		j, _ := json.Marshal(msg)
		log.Printf("posting webhook batchLen=%d totalSentBlocks=%d queuedBlocks=%d range=%d:%d payload=%s", batchLen, totalSentBlocks, queuedBlocks, totalSentBlocks, upper, string(j))
		// send rate is 1 message per second "burstable"
		time.Sleep(1 * time.Second)
		if err := slack.PostWebhook(app.Config.SlackWebhookURL, msg); err != nil {
			raw, _ := json.Marshal(&msg)
			log.Printf("Slack POST Webhook error=\"%s\" request=\"%s\"", err.Error(), string(raw))
		}
	}
}

func generateStatusFooterBlock(startTime time.Time, generalErrors []string, blocks *[]slack.Block) {
	generalErrors = append(generalErrors, fmt.Sprintf("Completed execution in %f", time.Since(startTime).Seconds()))
	execFooter := slack.NewTextBlockObject("mrkdwn", strings.Join(generalErrors, "\n"), false, false)
	*blocks = append(*blocks, slack.NewDividerBlock())
	*blocks = append(*blocks, slack.NewContextBlock("", execFooter))
}

func int32ExistsInArray(needle int32, haystack *[]int32) bool {
	for _, val := range *haystack {
		if val == needle {
			return true
		}
	}
	return false
}

func corpIsOnIgnoreList(needle int32, haystack *[]ignoredCorp) bool {
	for _, val := range *haystack {
		if val.CorpID == needle {
			return true
		}
	}
	return false
}

func characterIsOnIgnoreList(needle int32, haystack []ignoredCharacter) bool {
	for _, val := range haystack {
		if val.CharacterID == needle {
			return true
		}
	}
	return false
}

func characterExistsInNeucore(needle int64, haystack []neucoreapi.Character) bool {
	for _, val := range haystack {
		if val.GetId() == needle {
			return true
		}
	}

	return false
}

func characterHasValidNeucoreToken(needle int64, haystack []neucoreapi.Character) bool {
	for _, val := range haystack {
		if val.GetId() == needle {
			return val.GetValidToken()
		}
	}

	// Character missing from neucore.
	return false
}

func playerBelongsToGroup(needle string, haystack []neucoreapi.Group) bool {
	for _, val := range haystack {
		if val.GetName() == needle {
			return true
		}
	}
	return false
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

func createCorpBlocks(results corpVerificationResult) []slack.Block {
	// iterate errors map
	var sb strings.Builder
	fmt.Fprintf(
		&sb,
		"*<https://evewho.com/corporation/%d|%s>* [CEO: <https://evewho.com/character/%d|%s> - <https://evewho.com/character/%d|%s>] %d Members",
		results.CorpID,
		results.CorpName,
		results.Ceo.GetId(),
		results.Ceo.Name,
		results.CeoMain.GetId(),
		results.CeoMain.Name,
		results.MemberCount,
	)
	for _, value := range results.Errors {
		fmt.Fprintf(&sb, "\n  :octagonal_sign: %s", value)
	}
	for _, value := range results.Warnings {
		fmt.Fprintf(&sb, "\n  :warning: %s", value)
	}
	for _, value := range results.Info {
		fmt.Fprintf(&sb, "\n  :information_source: %s", value)
	}

	blockText := sb.String()
	if len(blockText) > 3000 {
		blockText = blockText[:2985]
		open := strings.LastIndex(blockText, "<")
		close := strings.LastIndex(blockText, ">")
		if open > close {
			blockText = blockText[:open]
		}
		blockText += "\n--TRUNCATED--"
	}

	corpIssues := slack.NewTextBlockObject("mrkdwn", blockText, false, false)
	corpImage := slack.NewImageBlockElement(fmt.Sprintf("https://images.evetech.net/corporations/%d/logo", results.CorpID), results.CorpName)
	corpSection := slack.NewSectionBlock(corpIssues, nil, slack.NewAccessory(corpImage))

	return []slack.Block{corpSection}
}

func integerMin(a int, b int) int {
	if a <= b {
		return a
	}
	return b
}

func integer64Max(a int64, b int64) int64 {
	if a > b {
		return a
	}
	return b
}

func dateMax(a time.Time, b time.Time) time.Time {
	if a.After(b) {
		return a
	}
	return b
}

func (app *app) chunkNameRequest(naughtyIDs []int32, missingMembers []int32, invalidMembers []int32) ([]string, []string, error) {
	const NAME_POST_LIMIT = 1000
	if len(naughtyIDs) <= 0 {
		return []string{}, []string{}, nil
	}

	var missingMemberStrings, invalidMemberStrings []string
	naughtyCount := len(naughtyIDs)
	for i := 0; i < len(naughtyIDs); i += NAME_POST_LIMIT {
		batchIDs := naughtyIDs[i:integerMin(i+NAME_POST_LIMIT, naughtyCount)]
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

			if int32ExistsInArray(name.Id, &missingMembers) {
				missingMemberStrings = append(missingMemberStrings, fmt.Sprintf("<https://evewho.com/character/%d|%s>", name.Id, name.Name))
			} else {
				if int32ExistsInArray(name.Id, &invalidMembers) {
					invalidMemberStrings = append(invalidMemberStrings, fmt.Sprintf("<https://evewho.com/character/%d|%s>", name.Id, name.Name))
				}
			}
		}
	}

	return missingMemberStrings, invalidMemberStrings, nil
}
