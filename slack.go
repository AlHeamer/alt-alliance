package main

import (
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/slack-go/slack"
)

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

func generateStatusFooterBlock(startTime time.Time, generalErrors []string, blocks *[]slack.Block) {
	generalErrors = append(generalErrors, fmt.Sprintf("Completed execution in %f", time.Since(startTime).Seconds()))
	execFooter := slack.NewTextBlockObject("mrkdwn", strings.Join(generalErrors, "\n"), false, false)
	*blocks = append(*blocks, slack.NewDividerBlock())
	*blocks = append(*blocks, slack.NewContextBlock("", execFooter))
}

func (app *app) generateAndSendWebhook(startTime time.Time, generalErrors []string, blocks *[]slack.Block) {
	generateStatusFooterBlock(startTime, generalErrors, blocks)

	// slack has a 50 block limit per message, and 1 message per second limit ("burstable.")
	const blocksPerMessage = 50
	blockArray := *blocks
	queuedBlocks := len(blockArray)
	var batchLen int
	for totalSentBlocks := 0; totalSentBlocks < queuedBlocks; totalSentBlocks += batchLen {
		upper := min(totalSentBlocks+blocksPerMessage, queuedBlocks)
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
		if err := slack.PostWebhook(app.config.SlackWebhookURL, msg); err != nil {
			raw, _ := json.Marshal(&msg)
			log.Printf("Slack POST Webhook error=\"%s\" request=\"%s\"", err.Error(), string(raw))
		}
	}
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
