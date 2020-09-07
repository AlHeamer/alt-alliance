package main

import (
	"context"
	"encoding/base64"
	"errors"
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

func (app *app) initDB() {
	var err error

	// Setup DB
	user := "root"
	password := ""
	host := "/tmp/mysql.sock"
	dbName := "alt_alliance"
	sqlString := "%s:%s@%s/%s?charset=utf8&parseTime=True&loc=Local"
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
	httpc := &http.Client{Timeout: time.Second * 10}
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
	initComplete := time.Now().Sub(startTime)
	log.Printf("Init Complete: %f", initComplete.Seconds())

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
	apiCheckComplete := time.Now().Sub(startTime)
	log.Printf("API Check Complete: %f", apiCheckComplete.Seconds())

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
	allianceCheckComplete := time.Now().Sub(startTime)
	log.Printf("Alliance Check Complete: %f", allianceCheckComplete.Seconds())

	// check each corp in the alliance
	separator := slack.NewDividerBlock()
	queueLength = len(allCorps)
	queue = make(chan int32, queueLength)
	var corpIgnoreList []corpIgnoreList
	app.DB.Select("corp_id").Find(&corpIgnoreList)
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
				corpVerificationResult := app.verifyCorporation(corpID, startTime)

				mutex.Lock()
				blocks = append(blocks, createCorpBlocks(corpVerificationResult)...)
				blocks = append(blocks, separator)
				mutex.Unlock()
			}
		}()
	}

	for i := 0; i < queueLength; i++ {
		queue <- allCorps[i]
	}
	close(queue)
	wg.Wait()
	corpCheckComplete := time.Now().Sub(startTime)
	log.Printf("Corp Check Complete: %f", corpCheckComplete.Seconds())

	app.generateAndSendWebhook(startTime, generalErrors, &blocks)
}

func (app *app) verifyCorporation(corpID int32, startTime time.Time) corpVerificationResult {
	results := corpVerificationResult{CorpID: corpID}

	corpIssues := []string{}
	corpData, _, err := app.ESI.ESI.CorporationApi.GetCorporationsCorporationId(nil, corpID, nil)
	if err != nil {
		log.Printf("ESI: Error getting public corp info - %s", err.Error())
		corpIssues = append(corpIssues, "ESI: Error getting public corp info - "+err.Error())
	}
	results.CorpName = corpData.Name
	ceoStringID := optional.NewString(fmt.Sprintf("%d", corpData.CeoId))

	results.Ceo = neucoreapi.Character{Id: int64(corpData.CeoId)}
	results.Ceo.Name = fmt.Sprintf("%d", corpData.CeoId)
	results.CeoMain = neucoreapi.Character{}
	results.CeoMain, _, err = app.Neu.ApplicationCharactersApi.MainV2(app.NeucoreContext, corpData.CeoId)
	if err != nil {
		log.Printf("Error retreiving CEO main from Neucore: [%d] %s", corpData.CeoId, err.Error())
		corpIssues = append(corpIssues, err.Error())
		results.Errors = append(results.Errors, corpIssues...)
		return results
	}

	///
	/// Check CEO's notifications (cached 10 minutes)
	///
	notificationOps := &esi.GetCharactersCharacterIdNotificationsOpts{Datasource: ceoStringID}
	notifications, _, err := app.ProxyESI.ESI.CharacterApi.GetCharactersCharacterIdNotifications(app.ProxyAuthContext, corpData.CeoId, notificationOps)
	if err != nil {
		log.Printf("Proxy: Error getting ceo notifications - %s", err.Error())
	}

	for _, notif := range notifications {
		msg := ""
		if notif.Type_ == "CorpBecameWarEligible" {
			msg = "Became War Eligible"
		} else if notif.Type_ == "CorpNoLongerWarEligible" {
			msg = "No Longer War Eligible"
		}

		if msg != "" {
			y, m, d := notif.Timestamp.Date()
			h, mm, s := notif.Timestamp.Clock()
			date := fmt.Sprintf("%d-%d-%d %d:%d:%d", y, m, d, h, mm, s)
			corpIssues = append(corpIssues, fmt.Sprintf("%s at %s", msg, date))
		}
	}
	log.Printf("Parsed CEO's notifications after %f", time.Now().Sub(startTime).Seconds())

	///
	/// Check corp info and member lists (cached 1 hour)
	///
	{
		if corpData.TaxRate < app.Config.CorpBaseTaxRate {
			corpIssues = append(corpIssues, fmt.Sprintf("Tax rate is %.f%% (expected at least %.f%%)", corpData.TaxRate*100, app.Config.CorpBaseTaxRate*100))
		}
		if corpData.WarEligible {
			corpIssues = append(corpIssues, "Corporation is War Eligible")
		}
		log.Printf("Corp Data retrieved after %f", time.Now().Sub(startTime).Seconds())

		neuCharacters, _, err := app.Neu.ApplicationCharactersApi.CorporationCharactersV1(app.NeucoreContext, corpID)
		if err != nil {
			log.Printf("Neu: Error getting characters corp %d %s", corpID, corpData.Name)
			corpIssues = append(corpIssues, fmt.Sprintf("Neu: Error getting characters for corp %d %s", corpID, corpData.Name))
		}

		// Datasource changes based on what corp you're querying, use the CEO's charID.
		corpMembersOpts := &esi.GetCorporationsCorporationIdMembersOpts{Datasource: ceoStringID}
		corpMembers, _, err := app.ProxyESI.ESI.CorporationApi.GetCorporationsCorporationIdMembers(app.ProxyAuthContext, corpID, corpMembersOpts)
		if err != nil {
			log.Printf("Proxy: Error corp members - %s", err.Error())
		}
		log.Printf("Player Characters retrieved after %f", time.Now().Sub(startTime).Seconds())

		naughtyMembers := corpMembers[:0]
		for _, char := range corpMembers {
			if !characterExistsInNeucore(int64(char), neuCharacters) {
				naughtyMembers = append(naughtyMembers, char)
			}
		}

		numBadMembers := len(naughtyMembers)
		var naughtyMemberNames []string
		chunkSize := 5
		chars := naughtyMembers[0:chunkSize]
		names, _, err := app.ESI.ESI.UniverseApi.PostUniverseNames(nil, chars, nil)
		if err != nil {
			log.Printf("Error retreiving bulk character names - %s", err.Error())
			results.Errors = append(results.Errors, "Error retreiving bulk character names - "+err.Error())
		}
		for _, name := range names {
			if name.Category != "character" {
				continue
			}
			naughtyMemberNames = append(naughtyMemberNames, fmt.Sprintf("<https://evewho.com/character/%d|%s>,", name.Id, name.Name))
		}
		naughtyMemberNames = append(naughtyMemberNames, fmt.Sprintf(" and %d more...", numBadMembers-chunkSize))

		corpIssues = append(corpIssues, fmt.Sprintf("Characters with invlalid tokens, or not in Neucore: %d/%d\n%v", numBadMembers, corpData.MemberCount, naughtyMemberNames))
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
		corpIssues = append(corpIssues, fmt.Sprintf("Bounty Payments Due: %.2f", bountyTotal))
		log.Printf("Calculated bounty payments after %f", time.Now().Sub(startTime).Seconds())
	}

	results.Errors = corpIssues
	return results
}

func (app *app) generateAndSendWebhook(startTime time.Time, generalErrors []string, blocks *[]slack.Block) {
	generateStatusFooterBlock(startTime, generalErrors, blocks)
	m := slack.Blocks{BlockSet: *blocks}
	msg := slack.WebhookMessage{
		Blocks: &m,
	}

	err := slack.PostWebhook(app.Config.SlackWebhookURL, &msg)
	if err != nil {
		log.Printf(err.Error())
	}
}

func generateStatusFooterBlock(startTime time.Time, generalErrors []string, blocks *[]slack.Block) {
	str := ""
	for _, g := range generalErrors {
		str += g
	}
	execTime := fmt.Sprintf("Completed execution in %f", time.Now().Sub(startTime).Seconds())
	execFooter := slack.NewTextBlockObject("mrkdwn", str+"\n"+execTime, false, false)
	*blocks = append(*blocks, slack.NewContextBlock("", execFooter))
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
	fmt.Fprintf(&sb, "*<https://evewho.com/corporation/%d|%s>*", results.CorpID, results.CorpName)
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
	corpFooter := slack.NewTextBlockObject(
		"mrkdwn",
		fmt.Sprintf(
			"<https://evewho.com/character/%d|CEO: %s> (Main: <https://evewho.com/character/%d|%s>)",
			results.Ceo.Id,
			results.Ceo.Name,
			results.CeoMain.Id,
			results.CeoMain.Name),
		false,
		false,
	)
	corpContext := slack.NewContextBlock("", []slack.MixedElement{corpFooter}...)

	return []slack.Block{corpSection, corpContext}
}
