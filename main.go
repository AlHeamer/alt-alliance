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
	log.Printf(connArgs)
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
		Expiry:      time.Now().Add(3600 * time.Second),
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

	// configure
	var app app
	app.initDB()
	//app.Config = config{}
	app.DB.First(&app.Config)
	app.Config.NeucoreAPIBase = fmt.Sprintf("%s://%s/api", app.Config.NeucoreHTTPScheme, app.Config.NeucoreDomain)
	if app.Config.CorpJournalUpdateIntervalHours == 0 {
		app.Config.CorpJournalUpdateIntervalHours = 1
	}

	// Init DB, ESI, Neucore
	app.initApp()
	log.Printf("Init Complete: %f", time.Now().Sub(startTime).Seconds())

	// Perform ESI Health check.
	var blocks []slack.Block
	generalErrors, err := app.esiHealthCheck()
	if err != nil {
		log.Printf("%s error=\"%s\"", generalErrors[0], err.Error())
		app.generateAndSendWebhook(startTime, generalErrors, &blocks)
		return
	}

	// Neucore Roles Check
	appData, _, err := app.Neu.ApplicationApi.ShowV1(app.NeucoreContext)
	if err != nil {
		neucoreError := fmt.Sprintf("Error checking neucore app info. error=\"%s\"", err.Error())
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
	var allianceCheckList []checkedAlliance
	var corpCheckList []checkedCorp
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
	if totalOwed > 1000000000 {
		generalErrors = append(generalErrors, fmt.Sprintf("Total corp taxes owed=%.f", totalOwed))
	}
	log.Printf("Corp Check Complete: %f", time.Now().Sub(startTime).Seconds())

	app.generateAndSendWebhook(startTime, generalErrors, &blocks)
}

func (app *app) verifyCorporation(corpID int32, charIgnoreList *[]ignoredCharacter, startTime time.Time) corpVerificationResult {
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
			msg = fmt.Sprintf("%s at %s", msg, notif.Timestamp.Format(dateTimeFormat))
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
			results.Errors = append(results.Errors, fmt.Sprintf("Error getting characters from Neucore. error=\"%s\"", err.Error()))
		}

		// Datasource changes based on what corp you're querying, use the CEO's charID.
		corpMembersOpts := &esi.GetCorporationsCorporationIdMembersOpts{Datasource: ceoStringID}
		corpMembers, response, err := app.ProxyESI.ESI.CorporationApi.GetCorporationsCorporationIdMembers(app.ProxyAuthContext, corpID, corpMembersOpts)
		if err != nil {
			logline := fmt.Sprintf("Proxy: Error getting characters for corp from esi. corpID=%d error=\"%s\"", corpID, err.Error())
			log.Printf(logline)
			if response.StatusCode == http.StatusForbidden {
				results.Errors = append(results.Errors, "Re-auth corp CEO: Needs ESI scope for member list.")
			} else {
				results.Errors = append(results.Errors, logline)
			}
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
				results.Info = append(results.Info, "Error retreiving character names.")
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
	{
		const masterWallet = 1 // Taxes always go to master wallet
		var taxData corpBalance
		app.DB.FirstOrInit(&taxData, corpBalance{CorpID: corpID})
		maxTransactionID := taxData.LastTransactionID
		maxTransactionDate := taxData.LastTransactionDate
		maxPaymentID := taxData.LastPaymentID

		lastUpdateOlderThanInterval := taxData.LastTransactionDate.Add(time.Hour * time.Duration(app.Config.CorpJournalUpdateIntervalHours)).Before(now)
		itsTheFirst := now.Day() == 1
		feeChargedToday := now.YearDay() == taxData.FeeAddedDate.YearDay()

		if lastUpdateOlderThanInterval || (itsTheFirst && !feeChargedToday) {
			// Get first page
			journalRolesOk := true
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

			if itsTheFirst && !feeChargedToday {
				taxData.FeeAddedDate = now
				runningBalance += app.Config.CorpBaseFee
				log.Printf("Monthly fee added to balance. corpID=%d date=\"%s\" fee=%.2f balance=%.2f",
					corpID,
					now.Format(dateTimeFormat),
					app.Config.CorpBaseFee,
					runningBalance,
				)
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

			if itsTheFirst && !feeChargedToday {
				mail := esi.PostCharactersCharacterIdMailMail{
					ApprovedCost: 0,
					Recipients: []esi.PostCharactersCharacterIdMailRecipient{
						{RecipientId: corpData.CeoId, RecipientType: "character"},
					},
					Subject: fmt.Sprintf(app.Config.EvemailSubject, now.Format(dateFormat)),
					Body:    fmt.Sprintf(app.Config.EvemailBody, taxData.Balance),
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
		}

		results.TaxOwed = taxData.AmountOwed
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

func generateStatusFooterBlock(startTime time.Time, generalErrors []string, blocks *[]slack.Block) {
	generalErrors = append(generalErrors, fmt.Sprintf("Completed execution in %f", time.Now().Sub(startTime).Seconds()))
	execFooter := slack.NewTextBlockObject("mrkdwn", strings.Join(generalErrors, "\n"), false, false)
	*blocks = append(*blocks, slack.NewDividerBlock())
	*blocks = append(*blocks, slack.NewContextBlock("", execFooter))
}

func characterIsOnIgnoreList(needle int32, haystack *[]ignoredCharacter) bool {
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

	corpIssues := slack.NewTextBlockObject("mrkdwn", sb.String(), false, false)
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
