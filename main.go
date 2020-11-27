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
	NeucoreAppID                   uint
	Threads                        int `gorm:"default:20"`
	CorpTaxCharacterID             int32
	CorpTaxCorpID                  int32
	CorpBaseTaxRate                float32
	CorpBaseFee                    float64
	RequestTimeoutInSeconds        int64  `gorm:"default:120"`
	CorpJournalUpdateIntervalHours uint16 `gorm:"default:24"`
	NeucoreHTTPScheme              string `gorm:"default:'http'"`
	NeucoreDomain                  string
	NeucoreAppSecret               string
	NeucoreUserAgent               string
	NeucoreAPIBase                 string
	EsiUserAgent                   string
	SlackWebhookURL                string
	EvemailSubject                 string
	EvemailBody                    string `gorm:"type:text"`
}

type app struct {
	Config           config
	DB               *gorm.DB
	ESI              *goesi.APIClient
	ProxyESI         *goesi.APIClient
	Neu              *neucoreapi.APIClient
	NeucoreContext   context.Context
	ProxyAuthContext context.Context
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
}

type ignoredCharacter struct {
	gorm.Model
	CharacterID int32
}

type corpBalance struct {
	CorpID              int32 `gorm:"PRIMARY_KEY"`
	LastTransactionID   int64
	LastPaymentID       int64
	Balance             float64 // Amount owed to holding corp
	LastTransactionDate time.Time
	FeeAddedDate        time.Time `gorm:"default:'1970-01-01 00:00:00'"`
	CorpName            string
}

type corpTaxPayment struct {
	gorm.Model
	CorpID        int32
	JournalID     int64
	PaymentAmount float64
	Balance       float64
	PaymentDate   time.Time
}

type corpVerificationResult struct {
	CorpID   int32
	CorpName string
	TaxOwed  float64
	Ceo      neucoreapi.Character
	CeoMain  neucoreapi.Character
	Errors   []string
	Warnings []string
	Info     []string
	Status   []string
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

	flag.StringVar(&user, "u", user, "The username used to access the database.")
	flag.StringVar(&password, "p", password, "The password for the user.")
	flag.StringVar(&host, "h", host, "The hostname of the database to connect to (can be a unix socket, ip address, or domain.)")
	flag.StringVar(&dbName, "d", dbName, "The name of the database to use.")
	flag.Parse()

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
	app.DB.AutoMigrate(&corpBalance{})
	app.DB.AutoMigrate(&corpTaxPayment{})
}

func (app *app) initApp() {
	// Init ESI
	httpc := &http.Client{Timeout: time.Second * time.Duration(app.Config.RequestTimeoutInSeconds)}
	app.ESI = goesi.NewAPIClient(httpc, app.Config.EsiUserAgent)

	// Init Neucore ESI Proxy
	app.ProxyESI = goesi.NewAPIClient(httpc, app.Config.NeucoreUserAgent)
	app.ProxyESI.ChangeBasePath(app.Config.NeucoreAPIBase + "/app/v1/esi")
	proxyAuth := goesi.NewSSOAuthenticatorV2(httpc, "", "", "", []string{})
	proxyToken := &oauth2.Token{
		AccessToken: base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%d:%s", app.Config.NeucoreAppID, app.Config.NeucoreAppSecret))),
		TokenType:   "bearer",
		Expiry:      time.Now().Add(httpc.Timeout),
	}
	neucoreTokenSource := proxyAuth.TokenSource(proxyToken)
	app.ProxyAuthContext = context.WithValue(context.Background(), goesi.ContextOAuth2, neucoreTokenSource)

	// Init Neucore API
	neucoreConfig := &neucoreapi.Configuration{
		HTTPClient: httpc,
		UserAgent:  app.Config.NeucoreUserAgent,
		BasePath:   app.Config.NeucoreAPIBase,
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
	if app.Config.CorpJournalUpdateIntervalHours == 0 {
		app.Config.CorpJournalUpdateIntervalHours = 1
	}

	// Init ESI, Neucore
	app.initApp()
	log.Printf("Init Complete: %f", time.Now().Sub(startTime).Seconds())

	// Perform ESI Health check.
	var blocks []slack.Block
	generalErrors, err := app.esiHealthCheck()
	if err != nil {
		app.generateAndSendWebhook(startTime, generalErrors, &blocks)
		return
	}

	// Neucore Roles Check
	neucoreAppData, _, err := app.Neu.ApplicationApi.ShowV1(app.NeucoreContext)
	if err != nil {
		neucoreError := fmt.Sprintf("Error checking neucore app info. error=\"%s\"", err.Error())
		log.Printf(neucoreError)
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
	log.Printf("API Check Complete: %f", time.Now().Sub(startTime).Seconds())

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
				allianceCorps, _, err := app.ESI.ESI.AllianceApi.GetAlliancesAllianceIdCorporations(nil, allianceID, nil)
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
	wg.Wait()
	log.Printf("Alliance Check Complete: %f", time.Now().Sub(startTime).Seconds())

	// check each corp in the alliance
	queueLength = len(allCorps)
	queue = make(chan int32, queueLength)
	var corpIgnoreList []ignoredCorp
	var charIgnoreList []ignoredCharacter
	app.DB.Select("corp_id").Find(&corpIgnoreList)
	app.DB.Select("character_id").Find(&charIgnoreList)
	var totalOwed float64
	taxMutex := &sync.Mutex{}
	for i := 0; i < app.Config.Threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for corpID := range queue {
				for _, ignoreCorp := range corpIgnoreList {
					if corpID == ignoreCorp.CorpID {
						log.Printf("Ignored Corporation id=%d", corpID)
						continue
					}
				}

				corpResult := app.verifyCorporation(corpID, &charIgnoreList, startTime)
				taxMutex.Lock()
				totalOwed += corpResult.TaxOwed
				taxMutex.Unlock()

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
	log.Printf("Corp Check Complete: %f", time.Now().Sub(startTime).Seconds())

	app.generateAndSendWebhook(startTime, generalErrors, &blocks)
}

func (app *app) verifyCorporation(corpID int32, charIgnoreList *[]ignoredCharacter, startTime time.Time) corpVerificationResult {
	now := time.Now()
	results := corpVerificationResult{
		CorpID:   corpID,
		CorpName: fmt.Sprintf("Corp %d", corpID),
		Ceo:      neucoreapi.Character{Name: "CEO"},
		CeoMain:  neucoreapi.Character{Name: "???"},
	}

	// Get public corp data
	corpData, _, err := app.ESI.ESI.CorporationApi.GetCorporationsCorporationId(nil, corpID, nil)
	if err != nil {
		logline := fmt.Sprintf("ESI: Error getting public corp info. corpID=%d error=\"%s\"", corpID, err.Error())
		log.Print(logline)
		results.Errors = append(results.Errors, "Error getting public corp info.")
		return results
	}
	results.CorpName = corpData.Name
	results.Ceo.Id = int64(corpData.CeoId)
	results.Ceo.Name = fmt.Sprintf("%d", corpData.CeoId)
	log.Printf("Corp Data retrieved after %f", time.Now().Sub(startTime).Seconds())

	// Get CEO info from neucore
	neuMain, response, err := app.Neu.ApplicationCharactersApi.MainV2(app.NeucoreContext, corpData.CeoId)
	if err != nil {
		logline := fmt.Sprintf("Neu: Error retreiving CEO's main. ceoID=%d error=\"%s\"", corpData.CeoId, err.Error())
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
	app.checkCeoNotifications(corpID, &corpData, &results, now, startTime)

	///
	/// Check corp info and member lists (cached 1 hour)
	///
	if corpData.TaxRate < app.Config.CorpBaseTaxRate {
		results.Errors = append(results.Errors, fmt.Sprintf("Tax rate is %.f%% (expected at least %.f%%)", corpData.TaxRate*100, app.Config.CorpBaseTaxRate*100))
	}
	if corpData.WarEligible {
		results.Errors = append(results.Errors, "Corporation is War Eligible.")
	}
	app.discoverNaughtyMembers(corpID, &corpData, &results, charIgnoreList, startTime)

	///
	/// Read corp wallet and update owed balance. Should run less often (min 1h, max 30d)
	///
	// app.updateBountyBalance(corpID, &corpData, &results, now, startTime)

	return results
}

func (app *app) checkCeoNotifications(corpID int32, corpData *esi.GetCorporationsCorporationIdOk, results *corpVerificationResult, now time.Time, startTime time.Time) {
	ceoStringID := optional.NewString(results.Ceo.Name)
	notificationOps := &esi.GetCharactersCharacterIdNotificationsOpts{Datasource: ceoStringID}
	notifications, response, err := app.ProxyESI.ESI.CharacterApi.GetCharactersCharacterIdNotifications(app.ProxyAuthContext, corpData.CeoId, notificationOps)
	if err != nil {
		log.Printf("Proxy: Error getting ceo notifications corpID=%d ceoID=%d error=\"%s\"", corpID, corpData.CeoId, err.Error())
		if response.StatusCode == http.StatusForbidden {
			results.Warnings = append(results.Warnings, "Re-auth corp CEO: Needs ESI scope for notifications.")
		} else {
			results.Warnings = append(results.Warnings, fmt.Sprintf("Error getting CEO's notifications. error=\"%s\"", err.Error()))
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
			msg = "No longer war eligible"
			msgLevel = &results.Info
		case "CorpBecameWarEligible":
			msg = "Became war eligible"
		case "StructureAnchoring":
			msg = "Has a structure anchoring"
		case "StructureOnline":
			msg = "Has onlined a structure"
		}

		if msg != "" {
			msg = fmt.Sprintf("%s at %s", msg, notif.Timestamp.Format(dateTimeFormat))
			*msgLevel = append(*msgLevel, msg)
		}
	}

	log.Printf("Parsed CEO's notifications after %f", time.Now().Sub(startTime).Seconds())
}

func (app *app) discoverNaughtyMembers(corpID int32, corpData *esi.GetCorporationsCorporationIdOk, results *corpVerificationResult, charIgnoreList *[]ignoredCharacter, startTime time.Time) {
	const defaultChunkSize = 30
	// Datasource changes based on what corp you're querying, use the CEO's charID.
	ceoStringID := optional.NewString(results.Ceo.Name)
	corpMembersOpts := &esi.GetCorporationsCorporationIdMembersOpts{Datasource: ceoStringID}
	corpMembers, response, err := app.ProxyESI.ESI.CorporationApi.GetCorporationsCorporationIdMembers(app.ProxyAuthContext, corpID, corpMembersOpts)
	if err != nil {
		logline := fmt.Sprintf("Proxy: Error getting characters for corp from esi. corpID=%d error=\"%s\"", corpID, err.Error())
		log.Printf(logline)
		switch response.StatusCode {
		default:
			results.Errors = append(results.Errors, logline)
		case http.StatusForbidden:
			results.Errors = append(results.Errors, "Re-auth corp CEO: Needs ESI scope for member list.")
		}
	}
	log.Printf("ESI Corp Members retrieved after %f", time.Now().Sub(startTime).Seconds())

	// Get member list from Neucore
	neuCharacters, _, err := app.Neu.ApplicationCharactersApi.CorporationCharactersV1(app.NeucoreContext, corpID)
	if err != nil {
		log.Printf("Neu: Error getting characters for corp from neucore. corpID=%d error=\"%s\"", corpID, corpData.Name)
		results.Errors = append(results.Errors, fmt.Sprintf("Error getting characters from Neucore. error=\"%s\"", err.Error()))
	}
	log.Printf("Neucore Corp Members retrieved after %f", time.Now().Sub(startTime).Seconds())

	var missingMembers []int32
	var invalidMembers []int32
	for _, char := range corpMembers {
		if !characterExistsInNeucore(int64(char), &neuCharacters) {
			if characterIsOnIgnoreList(char, charIgnoreList) {
				log.Printf("Ignored Character missing from neucore id=%d", char)
				continue
			}
			missingMembers = append(missingMembers, char)
		} else {
			if !characterHasValidNeucoreToken(int64(char), &neuCharacters) {
				if characterIsOnIgnoreList(char, charIgnoreList) {
					log.Printf("Ignored Character with invalid neucore token id=%d", char)
					continue
				}
				invalidMembers = append(invalidMembers, char)
			}
		}
	}

	// Get member names from ESI
	chunkSize := defaultChunkSize
	naughtyIDs := append(missingMembers, invalidMembers...)
	if len(naughtyIDs) > 0 {
		naughtyNames, _, err := app.ESI.ESI.UniverseApi.PostUniverseNames(nil, naughtyIDs, nil)
		if err != nil {
			log.Printf("Error retreiving bulk character names request=\"%v\" error=\"%s\"", naughtyIDs, err.Error())
			results.Info = append(results.Info, "Error retreiving character names.")
		}

		// missing members
		numMissingMembers := len(missingMembers)
		if chunkSize > numMissingMembers {
			chunkSize = numMissingMembers
		}
		chars := missingMembers[:chunkSize]
		var missingMemberStrings []string
		for _, name := range naughtyNames {
			if name.Category != "character" {
				continue
			}
			missingMemberStrings = append(missingMemberStrings, fmt.Sprintf("<https://evewho.com/character/%d|%s>", name.Id, name.Name))
		}
		if numMissingMembers > chunkSize {
			missingMemberStrings = append(missingMemberStrings, fmt.Sprintf("and %d more...", numMissingMembers-chunkSize))
		}
		results.Errors = append(results.Errors, fmt.Sprintf("Characters not in Neucore: %d/%d\n%s", numMissingMembers, corpData.MemberCount, strings.Join(missingMemberStrings, ", ")))

		// invalid members
		chunkSize = defaultChunkSize
		var invalidMemberStrings []string
		numInvalidMembers := len(invalidMembers)
		if chunkSize > numInvalidMembers {
			chunkSize = numInvalidMembers
		}
		chars = invalidMembers[:chunkSize]
		for _, name := range naughtyNames {
			if name.Category != "character" {
				continue
			}
			invalidMemberStrings = append(invalidMemberStrings, fmt.Sprintf("<https://evewho.com/character/%d|%s>", name.Id, name.Name))
		}
		if numInvalidMembers > chunkSize {
			invalidMemberStrings = append(invalidMemberStrings, fmt.Sprintf("and %d more...", numInvalidMembers-chunkSize))
		}
		results.Errors = append(results.Errors, fmt.Sprintf("Characters with invalid Neucore tokens: %d/%d\n%s", numInvalidMembers, corpData.MemberCount, strings.Join(invalidMemberStrings, ", ")))
	}

	/// Check for characters in Neucore, but lacking 'member' group (no chars in brave proper, or gone inactive)
	charGroups, _, err := app.Neu.ApplicationGroupsApi.GroupsBulkV1(app.NeucoreContext, corpMembers)
	if err != nil {
		log.Printf("Neu: Error retreiving bulk character groups error=\"%s\"", err.Error())
	}

	var groupMemberIDs []int32
	var groupMemberNames []string
	for _, char := range charGroups {
		if !playerBelongsToGroup("member", &char.Groups) {
			groupMemberIDs = append(groupMemberIDs, int32(char.Character.Id))
			groupMemberNames = append(groupMemberNames, char.Character.Name)
		}
	}

	var nonMemberCharacters []int32
	for _, char := range groupMemberIDs {
		if !characterIsAlreadyNaughty(char, &naughtyIDs) { // naughtyIDs is missing from neucore + invalid esi token
			nonMemberCharacters = append(nonMemberCharacters, char)
		}
	}

	chunkSize = defaultChunkSize
	var naughtyMemberStrings []string
	numBadMembers := len(nonMemberCharacters)
	if numBadMembers > 0 {
		if chunkSize > numBadMembers {
			chunkSize = numBadMembers
		}

		chars := nonMemberCharacters[:chunkSize]
		for i := range chars {
			naughtyMemberStrings = append(naughtyMemberStrings, fmt.Sprintf("<%s://%s/#UserAdmin/%d|%s>", app.Config.NeucoreHTTPScheme, app.Config.NeucoreDomain, nonMemberCharacters[i], naughtyNames[i]))
		}

		if numBadMembers > chunkSize {
			naughtyMemberStrings = append(naughtyMemberStrings, fmt.Sprintf("and %d more...", numBadMembers-chunkSize))
		}
		results.Warnings = append(results.Warnings, fmt.Sprintf("Characters without 'member' roles: %d/%d\n%s", numBadMembers, corpData.MemberCount, strings.Join(naughtyMemberStrings, ", ")))
	}

	log.Printf("Naughty list compiled after %f", time.Now().Sub(startTime).Seconds())
}

func (app *app) updateBountyBalance(corpID int32, corpData *esi.GetCorporationsCorporationIdOk, results *corpVerificationResult, now time.Time, startTime time.Time) {
	const masterWallet = 1 // Taxes always go to master wallet
	taxData := corpBalance{CorpID: corpID}
	app.DB.FirstOrInit(&taxData, corpBalance{CorpID: corpID, CorpName: corpData.Name, FeeAddedDate: time.Unix(1, 0)})
	maxTransactionID := taxData.LastTransactionID
	maxTransactionDate := taxData.LastTransactionDate
	maxPaymentID := taxData.LastPaymentID

	lastUpdateOlderThanInterval := taxData.LastTransactionDate.Add(time.Hour * time.Duration(app.Config.CorpJournalUpdateIntervalHours)).Before(now)
	itsTheFirst := now.Day() == 1
	feeChargedToday := now.YearDay() == taxData.FeeAddedDate.YearDay()

	if !lastUpdateOlderThanInterval && !(itsTheFirst && !feeChargedToday) {
		return
	}

	// Get first page
	journalRolesOk := true
	ceoStringID := optional.NewString(results.Ceo.Name)
	journalOpts := esi.GetCorporationsCorporationIdWalletsDivisionJournalOpts{Datasource: ceoStringID, Page: optional.NewInt32(1)}
	journal, response, err := app.ProxyESI.ESI.WalletApi.GetCorporationsCorporationIdWalletsDivisionJournal(app.ProxyAuthContext, corpID, masterWallet, &journalOpts)
	var pageReadIssues []string
	if err != nil {
		log.Printf("Proxy: Error reading journal corpID=%d page=%d ceoID=%d error=\"%s\"",
			corpID,
			journalOpts.Page.Value(),
			corpData.CeoId,
			err.Error(),
		)
		if response.StatusCode == http.StatusForbidden {
			journalRolesOk = false
			results.Warnings = append(results.Warnings, "Re-auth corp CEO: Needs ESI scope for wallet journals.")
		} else {
			pageReadIssues = append(pageReadIssues, fmt.Sprintf("Error reading corp wallet page=%d error=\"%s\"", journalOpts.Page.Value(), err.Error()))
		}
	}

	if journalRolesOk == true {
		numPages, _ := strconv.Atoi(response.Header.Get("X-Pages"))
		for i := 2; i < numPages; i++ {
			journalOpts.Page = optional.NewInt32(int32(i))
			page, _, err := app.ProxyESI.ESI.WalletApi.GetCorporationsCorporationIdWalletsDivisionJournal(app.ProxyAuthContext, corpID, masterWallet, &journalOpts)
			if err != nil {
				log.Printf("Proxy: Error reading journal corpID=%d page=%d ceoID=%d error=\"%s\"",
					corpID,
					journalOpts.Page.Value(),
					corpData.CeoId,
					err.Error(),
				)
				pageReadIssues = append(pageReadIssues, fmt.Sprintf("Error reading corp wallet page=%d error=\"%s\"", journalOpts.Page.Value(), err.Error()))
			}

			// Assume pages are sorted by transaction date descending
			if page[0].Date.Before(taxData.LastTransactionDate) || page[0].Date.Add(time.Hour*24*30).Before(now) {
				// Don't bother fetching pages that start with transactions older than a month and older than the last transaction date.
				break
			}
			journal = append(journal, page...)
		}
	}
	if len(pageReadIssues) > 0 {
		results.Warnings = append(results.Warnings, strings.Join(pageReadIssues, "\n"))
	}

	bountyTotal := 0.0
	paymentTotal := 0.0
	runningBalance := taxData.Balance
	var payments []corpTaxPayment
	for _, entry := range journal {
		if entry.Id > taxData.LastTransactionID {
			switch entry.RefType {

			case "bounty_prizes":
				amount := entry.Amount
				if corpData.TaxRate > app.Config.CorpBaseTaxRate {
					// calculate the alliance cut.
					amount = (amount / float64(corpData.TaxRate)) * float64(app.Config.CorpBaseTaxRate)
				}
				bountyTotal += amount
				runningBalance += amount

			case "corporation_account_withdrawal":
				if entry.SecondPartyId == app.Config.CorpTaxCorpID {
					payment := corpTaxPayment{
						CorpID:        entry.FirstPartyId,
						JournalID:     entry.Id,
						PaymentAmount: -1 * entry.Amount,
						Balance:       runningBalance + entry.Amount, // entry amount is negative. First balance in db could be negative
						PaymentDate:   entry.Date,
					}
					paymentTotal += payment.PaymentAmount
					payments = append(payments, payment)
					maxPaymentID = integer64Max(maxPaymentID, payment.JournalID)
					runningBalance += entry.Amount
				}
			}
		}

		maxTransactionID = integer64Max(maxTransactionID, entry.Id)
		maxTransactionDate = dateMax(maxTransactionDate, entry.Date)
	}

	if bountyTotal > 0 || paymentTotal > 0 {
		log.Printf(
			"Corp balance updated. corpID=%d bounties=%.2f payments=%.2f previousBalance=%.2f newBalance=%.2f lastTransactionID=%d lastTransactionDate=\"%s\"",
			corpID,
			bountyTotal,
			paymentTotal,
			taxData.Balance,
			runningBalance,
			maxTransactionID,
			maxTransactionDate,
		)
	}

	// Add monthly fee and send invoice via evemail
	if itsTheFirst && !feeChargedToday {
		taxData.FeeAddedDate = now
		runningBalance += app.Config.CorpBaseFee
		log.Printf("Monthly fee added to balance. corpID=%d date=\"%s\" fee=%.2f balance=%.2f",
			corpID,
			now.Format(dateTimeFormat),
			app.Config.CorpBaseFee,
			runningBalance,
		)

		mail := esi.PostCharactersCharacterIdMailMail{
			ApprovedCost: 0,
			Recipients: []esi.PostCharactersCharacterIdMailRecipient{
				{RecipientId: corpData.CeoId, RecipientType: "character"},
			},
			Subject: fmt.Sprintf(app.Config.EvemailSubject, now.Format(dateFormat)),
			Body:    fmt.Sprintf(app.Config.EvemailBody, fmt.Sprintf("%.f", taxData.Balance)),
		}

		mailOpts := esi.PostCharactersCharacterIdMailOpts{Datasource: optional.NewString(fmt.Sprintf("%d", app.Config.CorpTaxCharacterID))}
		mailID, _, err := app.ProxyESI.ESI.MailApi.PostCharactersCharacterIdMail(app.ProxyAuthContext, app.Config.CorpTaxCharacterID, mail, &mailOpts)
		if err != nil {
			log.Printf("Error sending invoice evemail. corpID=%d recipientID=%d senderID=%d balance=%.2f error=\"%s\"",
				corpID,
				corpData.CeoId,
				app.Config.CorpTaxCharacterID,
				taxData.Balance,
				err.Error(),
			)
			results.Info = append(results.Info, fmt.Sprintf("Failed to send invoice. Balance Due: %.2f", taxData.Balance))
		} else {
			log.Printf("Invoice sent via evemail. recipient=%d mailID=%d", corpData.CeoId, mailID)
		}
	}

	taxData.Balance = runningBalance
	taxData.LastTransactionID = maxTransactionID
	taxData.LastTransactionDate = maxTransactionDate
	taxData.LastPaymentID = maxPaymentID

	// for some reason we can't insert multiple rows at once :(
	//app.DB.Create(&payments)
	for _, payment := range payments {
		dbResult := app.DB.Create(&payment)
		if dbResult.Error != nil {
			logline := fmt.Sprintf("Error writing corp payment logs to db. corpID=%d journalID=%d error=\"%s\"",
				corpID,
				payment.JournalID,
				dbResult.Error.Error(),
			)
			log.Print(logline)
			results.Errors = append(results.Errors, logline)
		}
	}

	dbResult := app.DB.Save(&taxData)
	if dbResult.Error != nil {
		logline := fmt.Sprintf("Error writing corp balance to db. corpID=%d error=\"%s\"",
			corpID,
			dbResult.Error.Error(),
		)
		log.Print(logline)
		results.Errors = append(results.Errors, logline)
	}

	results.TaxOwed = taxData.Balance
	log.Printf("Bounty balance and fees updated after %f", time.Now().Sub(startTime).Seconds())
}

func (app *app) generateAndSendWebhook(startTime time.Time, generalErrors []string, blocks *[]slack.Block) {
	generateStatusFooterBlock(startTime, generalErrors, blocks)

	// slack has a 50 block limit per message, and 1 message per second limit ("burstable.")
	const blocksPerMessage = 50
	blockArray := *blocks
	numBlocks := len(blockArray)
	for sentBlocks := 0; sentBlocks < numBlocks; sentBlocks += blocksPerMessage {
		var batch []slack.Block
		batch = blockArray[sentBlocks:integerMin(sentBlocks+blocksPerMessage, numBlocks)]

		m := slack.Blocks{BlockSet: batch}
		msg := slack.WebhookMessage{
			Blocks: &m,
		}

		err := slack.PostWebhook(app.Config.SlackWebhookURL, &msg)
		if err != nil {
			raw, _ := json.Marshal(&msg)
			log.Printf("Slack POST Webhook error=\"%s\" request=\"%s\"", err.Error(), string(raw))
		}
	}
}

func generateStatusFooterBlock(startTime time.Time, generalErrors []string, blocks *[]slack.Block) {
	generalErrors = append(generalErrors, fmt.Sprintf("Completed execution in %f", time.Now().Sub(startTime).Seconds()))
	execFooter := slack.NewTextBlockObject("mrkdwn", strings.Join(generalErrors, "\n"), false, false)
	*blocks = append(*blocks, slack.NewDividerBlock())
	*blocks = append(*blocks, slack.NewContextBlock("", execFooter))
}

func characterIsAlreadyNaughty(needle int32, haystack *[]int32) bool {
	for _, val := range *haystack {
		if val == needle {
			return true
		}
	}
	return false
}

func characterIsOnIgnoreList(needle int32, haystack *[]ignoredCharacter) bool {
	for _, val := range *haystack {
		if val.CharacterID == needle {
			return true
		}
	}
	return false
}

func characterExistsInNeucore(needle int64, haystack *[]neucoreapi.Character) bool {
	for _, val := range *haystack {
		if val.Id == needle {
			return true
		}
	}

	return false
}

func characterHasValidNeucoreToken(needle int64, haystack *[]neucoreapi.Character) bool {
	for _, val := range *haystack {
		if val.Id == needle {
			return *val.ValidToken
		}
	}

	// Character missing from neucore.
	return false
}

func playerBelongsToGroup(needle string, haystack *[]neucoreapi.Group) bool {
	for _, val := range *haystack {
		if val.Name == needle {
			return true
		}
	}
	return false
}

func (app *app) esiHealthCheck() ([]string, error) {
	generalErrors := []string{}
	var err error
	status, _, err := app.ESI.Meta.MetaApi.GetStatus(nil, nil)
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
				endpoint.Route == "/corporations/{corporation_id}/wallets/{division}/journal/" || // private, ratting ISK and payments
				endpoint.Route == "/characters/{character_id}/notifications/" || // private, war and structure notifs
				endpoint.Route == "/characters/{character_id}/mail/" // private, sending evemails

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
		"*<https://evewho.com/corporation/%d|%s>* [CEO: <https://evewho.com/character/%d|%s> - <https://evewho.com/character/%d|%s>]",
		results.CorpID,
		results.CorpName,
		results.Ceo.Id,
		results.Ceo.Name,
		results.CeoMain.Id,
		results.CeoMain.Name,
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
