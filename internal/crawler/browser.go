package crawler

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/mxschmitt/playwright-go"
)

type CrawlerResult struct {
	URL        string
	DOMContent string
	HarFile    string
	Screenshot []byte
}

type StealthBrowser struct {
	pw      *playwright.Playwright
	browser playwright.Browser
}

func NewStealthBrowser() (*StealthBrowser, error) {
	err := playwright.Install()
	if err != nil {
		log.Printf("could not install playwright drivers: %v", err)
	}

	pw, err := playwright.Run()
	if err != nil {
		return nil, fmt.Errorf("could not start playwright: %w", err)
	}

	browser, err := pw.Chromium.Launch(playwright.BrowserTypeLaunchOptions{
		Headless: playwright.Bool(true),
		Args: []string{
			"--disable-blink-features=AutomationControlled",
		},
	})
	if err != nil {
		return nil, fmt.Errorf("could not launch browser: %w", err)
	}

	return &StealthBrowser{
		pw:      pw,
		browser: browser,
	}, nil
}

func (sb *StealthBrowser) Close() error {
	if err := sb.browser.Close(); err != nil {
		return err
	}
	return sb.pw.Stop()
}

func (sb *StealthBrowser) Crawl(ctx context.Context, targetURL string) (*CrawlerResult, error) {
	// Note: Proper stealth requires setting a unique/residential proxy and randomized User-Agent.
	// For this skeleton, we use default context options.
	bCtx, err := sb.browser.NewContext(playwright.BrowserNewContextOptions{
		UserAgent: playwright.String("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"),
	})
	if err != nil {
		return nil, err
	}
	defer bCtx.Close()

	page, err := bCtx.NewPage()
	if err != nil {
		return nil, err
	}
	
	// Enforce 30s timeout on navigation
	page.SetDefaultNavigationTimeout(30000)

	_, err = page.Goto(targetURL, playwright.PageGotoOptions{
		WaitUntil: playwright.WaitUntilStateNetworkidle,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to goto %s: %w", targetURL, err)
	}
	
	// Optional: add random sleep for anti-bot evasion
	time.Sleep(2 * time.Second)

	content, err := page.Content()
	if err != nil {
		return nil, err
	}

	screenshot, err := page.Screenshot(playwright.PageScreenshotOptions{
		FullPage: playwright.Bool(true),
	})
	if err != nil {
		log.Printf("warning: failed to capture screenshot for %s: %v", targetURL, err)
	}

	return &CrawlerResult{
		URL:        targetURL,
		DOMContent: content,
		Screenshot: screenshot,
	}, nil
}
