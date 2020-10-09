package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
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
	NeucoreHTTPScheme  string
	NeucoreDomain      string
	NeucoreAppID       uint
	NeucoreAppSecret   string
	NeucoreUserAgent   string
	NeucoreAPIBase     string
	EsiUserAgent       string
	SlackWebhookURL    string
	CorpBaseFee        float32
	CorpTaxCharacterID int32
	CorpTaxCorpID      int32
	CorpBaseTaxRate    float32
	Threads            int
}

type app struct {
	Config           config
	DB               *gorm.DB
	ESI              *goesi.APIClient
	ProxyESI         *goesi.APIClient
	ProxyAuth        *goesi.SSOAuthenticator
	Neu              *neucoreapi.APIClient
	NeucoreContext   context.Context
	ProxyAuthContext context.Context
}

type allianceCheckList struct {
	ID         uint32
	AllianceID int32
}

type corpCheckList struct {
	ID     uint32
	CorpID int32
}

type corpIgnoreList struct {
	ID     uint32
	CorpID int32
}

type characterIgnoreList struct {
	ID          uint32
	CharacterID int32
}

type corpTaxOwed struct {
	CorpID              int32
	LastTransactionID   int64
	AmountOwed          float64
	LastTransactionDate time.Time
}

type corpTaxPaymentLog struct {
	CorpID        int32
	PaymentAmount float32
	JournalID     int64
	Date          time.Time
}

type corpVerificationResult struct {
	CorpID   int32
	CorpName string
	Ceo      neucoreapi.Character
	CeoMain  neucoreapi.Character
	Errors   []string
	Warnings []string
	Info     []string
	Status   []string
}

const dateFormat = "2006-01-02 15:04"

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
	log.Printf(connArgs)
	app.DB, err = gorm.Open("mysql", connArgs)
	if err != nil {
		log.Fatal(err.Error(), "\n\nDB connection error: Did you forget to specify database params?")
	}

	app.DB.AutoMigrate(&config{})
	app.DB.AutoMigrate(&allianceCheckList{})
	app.DB.AutoMigrate(&corpCheckList{})
	app.DB.AutoMigrate(&corpIgnoreList{})
	app.DB.AutoMigrate(&characterIgnoreList{})
	//app.DB.AutoMigrate(&corpTaxOwed{})
	//app.DB.AutoMigrate(&corpTaxPaymentLog{})
}

func (app *app) initApp() {
	// Init ESI
	httpc := &http.Client{Timeout: time.Second * 120}
	app.ESI = goesi.NewAPIClient(httpc, app.Config.EsiUserAgent)

	// Init Neucore ESI Proxy
	app.ProxyESI = goesi.NewAPIClient(httpc, app.Config.NeucoreUserAgent)
	app.ProxyESI.ChangeBasePath(app.Config.NeucoreAPIBase + "/app/v1/esi")
	app.ProxyAuth = goesi.NewSSOAuthenticatorV2(httpc, "", "", "", []string{})
	proxyToken := &oauth2.Token{
		AccessToken: base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%d:%s", app.Config.NeucoreAppID, app.Config.NeucoreAppSecret))),
		TokenType:   "bearer",
		Expiry:      time.Now().Add(3600 * time.Second),
	}
	neucoreTokenSource := app.ProxyAuth.TokenSource(proxyToken)
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

	// configure
	var app app
	app.initDB()
	//app.Config = config{}
	app.DB.First(&app.Config)
	app.Config.NeucoreAPIBase = fmt.Sprintf("%s://%s/api", app.Config.NeucoreHTTPScheme, app.Config.NeucoreDomain)

	// Init DB, ESI, Neucore
	app.initApp()
	log.Printf("Init Complete: %f", time.Now().Sub(startTime).Seconds())

	// Perform ESI Health check.
	var blocks []slack.Block
	generalErrors, err := app.esiHealthCheck()
	if err != nil {
		log.Printf("%s - %s", generalErrors[0], err.Error())
		app.generateAndSendWebhook(startTime, generalErrors, &blocks)
		return
	}

	// Neucore Roles Check
	appData, _, err := app.Neu.ApplicationApi.ShowV1(app.NeucoreContext)
	if err != nil {
		neucoreError := fmt.Sprintf("Error checking neucore app info - %v", err.Error())
		log.Printf(neucoreError)
		generalErrors = append(generalErrors, neucoreError)
		app.generateAndSendWebhook(startTime, generalErrors, &blocks)
		return
	}

	requiredRoles := []neucoreapi.Role{neucoreapi.APP, neucoreapi.APP_CHARS, neucoreapi.APP_ESI /*, neucoreapi.APP_GROUPS*/}
	for _, rr := range requiredRoles {
		success := false
		for _, role := range appData.Roles {
			if rr == role {
				success = true
			}
		}
		if !success {
			// dump and die
			msg := fmt.Sprintf("Neucore Config Error - Missing Roles:\nGiven: %v\nReq'd: %v", appData.Roles, requiredRoles)
			log.Print(msg)
			break
		}
	}
	log.Printf("API Check Complete: %f", time.Now().Sub(startTime).Seconds())

	// Get alliance list or die
	var allianceCheckList []allianceCheckList
	var corpCheckList []corpCheckList
	app.DB.Select("alliance_id").Find(&allianceCheckList)
	queueLength := len(allianceCheckList)
	queue := make(chan int32, queueLength)
	mutex := &sync.Mutex{}
	app.DB.Select("corp_id").Find(&corpCheckList)
	var allCorps []int32
	for _, corp := range corpCheckList {
		allCorps = append(allCorps, corp.CorpID)
	}
	wg := sync.WaitGroup{}
	for i := 0; i < app.Config.Threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for allianceID := range queue {
				allianceCorps, _, err := app.ESI.ESI.AllianceApi.GetAlliancesAllianceIdCorporations(nil, allianceID, nil)
				if err != nil {
					log.Printf("ESI Error getting alliance corp list for allianceID %d - %v", allianceID, err.Error())
					// dump and exit
					generalErrors = append(generalErrors, fmt.Sprintf("ESI Error getting alliance corp list for allianceID %d - %v", allianceID, err.Error()))
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
	var corpIgnoreList []corpIgnoreList
	var charIgnoreList []characterIgnoreList
	app.DB.Select("corp_id").Find(&corpIgnoreList)
	app.DB.Select("character_id").Find(&charIgnoreList)
	for i := 0; i < app.Config.Threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for corpID := range queue {
				for _, ignoreCorp := range corpIgnoreList {
					if corpID == ignoreCorp.CorpID {
						continue
					}
				}
				corpResult := app.verifyCorporation(corpID, &charIgnoreList, startTime)

				if len(corpResult.Errors) > 0 ||
					len(corpResult.Warnings) > 0 ||
					len(corpResult.Info) > 0 ||
					len(corpResult.Status) > 0 {
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
	log.Printf("Corp Check Complete: %f", time.Now().Sub(startTime).Seconds())

	app.generateAndSendWebhook(startTime, generalErrors, &blocks)
}

func (app *app) verifyCorporation(corpID int32, charIgnoreList *[]characterIgnoreList, startTime time.Time) corpVerificationResult {
	results := corpVerificationResult{CorpID: corpID, CorpName: fmt.Sprintf("Corp %d", corpID)}
	results.Ceo = neucoreapi.Character{Name: "CEO"}
	results.CeoMain = neucoreapi.Character{Name: "???"}

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
	ceoStringID := optional.NewString(results.Ceo.Name)

	neuMain, response, err := app.Neu.ApplicationCharactersApi.MainV2(app.NeucoreContext, corpData.CeoId)
	if err != nil {
		logline := fmt.Sprintf("Neu: Error retreiving CEO's main. ceoID=%d error=\"%s\"", corpData.CeoId, err.Error())
		log.Print(logline)
		switch response.StatusCode {
		case 404:
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
	notificationOps := &esi.GetCharactersCharacterIdNotificationsOpts{Datasource: ceoStringID}
	notifications, _, err := app.ProxyESI.ESI.CharacterApi.GetCharactersCharacterIdNotifications(app.ProxyAuthContext, corpData.CeoId, notificationOps)
	if err != nil {
		log.Printf("Proxy: Error getting ceo notifications corpID=%d ceoID=%d error=\"%s\"", corpID, corpData.CeoId, err.Error())
		results.Warnings = append(results.Warnings, "Error getting CEO's notifications.")
	}

	now := time.Now().UTC()
	for _, notif := range notifications {
		if notif.Timestamp.Add(time.Hour).Before(now) {
			continue
		}

		msg := ""
		msgLevel := &results.Errors
		switch notif.Type_ {
		case "CorpNoLongerWarEligible":
			msg = "No Longer War Eligible"
			msgLevel = &results.Info
		case "CorpBecameWarEligible":
			msg = "Became War Eligible"
		case "StructureAnchoring":
			msg = "Has a structure anchoring"
		case "StructureOnline":
			msg = "Has onlined a structure"
		}

		if msg != "" {
			msg = fmt.Sprintf("%s at %s", msg, notif.Timestamp.Format(dateFormat))
			*msgLevel = append(*msgLevel, msg)
		}
	}
	log.Printf("Parsed CEO's notifications after %f", time.Now().Sub(startTime).Seconds())

	///
	/// Check corp info and member lists (cached 1 hour)
	///
	{
		if corpData.TaxRate < app.Config.CorpBaseTaxRate {
			results.Errors = append(results.Errors, fmt.Sprintf("Tax rate is %.f%% (expected at least %.f%%)", corpData.TaxRate*100, app.Config.CorpBaseTaxRate*100))
		}
		if corpData.WarEligible {
			results.Errors = append(results.Errors, "Corporation is War Eligible.")
		}
		log.Printf("Corp Data retrieved after %f", time.Now().Sub(startTime).Seconds())

		neuCharacters, _, err := app.Neu.ApplicationCharactersApi.CorporationCharactersV1(app.NeucoreContext, corpID)
		if err != nil {
			log.Printf("Neu: Error getting characters for corp from neucore. corpID=%d error=\"%s\"", corpID, corpData.Name)
			results.Errors = append(results.Errors, "Error getting characters for from Neucore.")
		}

		// Datasource changes based on what corp you're querying, use the CEO's charID.
		corpMembersOpts := &esi.GetCorporationsCorporationIdMembersOpts{Datasource: ceoStringID}
		corpMembers, _, err := app.ProxyESI.ESI.CorporationApi.GetCorporationsCorporationIdMembers(app.ProxyAuthContext, corpID, corpMembersOpts)
		if err != nil {
			log.Printf("Proxy: Error getting characters for corp from esi. corpID=%d error=\"%s\"", corpID, err.Error())
		}
		log.Printf("Player Characters retrieved after %f", time.Now().Sub(startTime).Seconds())

		naughtyMembers := corpMembers[:0]
		for _, char := range corpMembers {
			if !characterExistsInNeucore(int64(char), neuCharacters) {
				if !characterIsOnIgnoreList(char, charIgnoreList) {
					naughtyMembers = append(naughtyMembers, char)
				}
			}
		}

		numBadMembers := len(naughtyMembers)
		if numBadMembers > 0 {
			var naughtyMemberNames []string
			chunkSize := 5
			if chunkSize > numBadMembers {
				chunkSize = numBadMembers
			}
			chars := naughtyMembers[0:chunkSize]
			names, _, err := app.ESI.ESI.UniverseApi.PostUniverseNames(nil, chars, nil)
			if err != nil {
				log.Printf("Error retreiving bulk character names request=\"%v\" error=\"%s\"", chars, err.Error())
				results.Info = append(results.Errors, "Error retreiving character names")
			}
			for _, name := range names {
				if name.Category != "character" {
					continue
				}
				naughtyMemberNames = append(naughtyMemberNames, fmt.Sprintf("<https://evewho.com/character/%d|%s>", name.Id, name.Name))
			}
			if numBadMembers > chunkSize {
				naughtyMemberNames = append(naughtyMemberNames, fmt.Sprintf("and %d more...", numBadMembers-chunkSize))
			}
			naughtyMemberString := strings.Join(naughtyMemberNames, ", ")

			results.Errors = append(results.Errors, fmt.Sprintf("Characters with invalid tokens, or not in Neucore: %d/%d\n%s", numBadMembers, corpData.MemberCount, naughtyMemberString))
		}

		log.Printf("Naughty list compiled after %f", time.Now().Sub(startTime).Seconds())
	}

	///
	/// Run less often, probably once per week (min 1h, max 30d)
	///
	if false {
		y, m, d := time.Now().Date()
		if d != 1 {
			results.Errors = append(results.Errors, fmt.Sprintf("Running Monthy Taxes on day %d, expected 1", d))
		}

		if m == 1 {
			y--
		}
		m--

		journalOpts := &esi.GetCorporationsCorporationIdWalletsDivisionJournalOpts{Datasource: ceoStringID}
		journal, response, err := app.ProxyESI.ESI.WalletApi.GetCorporationsCorporationIdWalletsDivisionJournal(app.ProxyAuthContext, corpID, 1, journalOpts)
		if err != nil {
			log.Printf("Proxy: Error reading journal - %s", err.Error())
		}

		numPages, _ := strconv.Atoi(response.Header.Get("X-Pages"))
		for i := 1; i < numPages; i++ {
			page, _, _ := app.ProxyESI.ESI.WalletApi.GetCorporationsCorporationIdWalletsDivisionJournal(app.ProxyAuthContext, corpID, 1, journalOpts)
			firstOfMonth := time.Date(y, m, 1, 0, 0, 0, 0, time.UTC)
			lastOfMonth := firstOfMonth.AddDate(0, 1, -1)
			if page[0].Date.After(firstOfMonth) {
				continue
			}
			if page[0].Date.Before(lastOfMonth) {
				journal = append(journal, page...)
			}
		}

		bountyTotal := 0.0
		for _, entry := range journal {
			if entry.RefType == "bounty_prizes" {
				bountyTotal += entry.Amount
			}
		}
		results.Errors = append(results.Errors, fmt.Sprintf("Bounty Payments Due: %.2f", bountyTotal))
		log.Printf("Calculated bounty payments after %f", time.Now().Sub(startTime).Seconds())
	}

	return results
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

func integerMin(a int, b int) int {
	if a <= b {
		return a
	}
	return b
}

func generateStatusFooterBlock(startTime time.Time, generalErrors []string, blocks *[]slack.Block) {
	generalErrors = append(generalErrors, fmt.Sprintf("Completed execution in %f", time.Now().Sub(startTime).Seconds()))
	execFooter := slack.NewTextBlockObject("mrkdwn", strings.Join(generalErrors, "\n"), false, false)
	*blocks = append(*blocks, slack.NewDividerBlock())
	*blocks = append(*blocks, slack.NewContextBlock("", execFooter))
}

func characterIsOnIgnoreList(needle int32, haystack *[]characterIgnoreList) bool {
	for _, val := range *haystack {
		if val.CharacterID == needle {
			return true
		}
	}
	return false
}

func characterExistsInNeucore(needle int64, haystack []neucoreapi.Character) bool {
	for _, val := range haystack {
		if val.Id == needle || *val.ValidToken == false {
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
		generalErrors = append(generalErrors, "Error getting ESI Status")
		return generalErrors, err
	}

	for _, endpoint := range status {
		if endpoint.Status != "green" {
			switch endpoint.Route {
			case "/alliances/{alliance_id}/corporations/": // public,  corp list
			case "/corporations/{corporation_id}/": // public,  tax rate
			case "/corporations/{corporation_id}/members/": // private, character list
			case "/corporations/{corporation_id}/wallets/{division}/journal/": // private, ratting ISK
			case "/characters/{character_id}/notifications/": // private, war notifs
				if err != nil && endpoint.Status == "red" {
					err = errors.New("one or more endpoint requests are not succeeding and/or are very slow (5s+) on average")
				}

				status := ":heart:"
				if endpoint.Status == "yellow" {
					status = ":yellow_heart:"
				}
				generalErrors = append(generalErrors, fmt.Sprintf("%s `%s`", status, endpoint.Route))
				break
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

	corpIssues := slack.NewTextBlockObject("mrkdwn", sb.String(), false, false)
	corpImage := slack.NewImageBlockElement(fmt.Sprintf("https://images.evetech.net/corporations/%d/logo", results.CorpID), results.CorpName)
	corpSection := slack.NewSectionBlock(corpIssues, nil, slack.NewAccessory(corpImage))

	return []slack.Block{corpSection}
}
