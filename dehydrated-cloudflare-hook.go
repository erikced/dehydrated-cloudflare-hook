package main

import (
	"fmt"
	"github.com/erikced/cfdns"
	"log"
	"os"
	"strings"
	"time"
)

const argsPerDomain = 3
const challengePrefix = "_acme-challenge."

func getZoneFromDomainName(domainName string) string {
	substrings := strings.SplitN(domainName, ".", strings.Count(domainName, "."))
	return substrings[len(substrings)-1]
}

func addChallengeRecords(client cfdns.Client, args []string) error {
	argsPerDomain := 3
	sleepDuration := time.Duration(30)
	for i := 0; i+2 < len(args); i += argsPerDomain {
		err := addChallengeRecord(client, args[i], args[i+2])
		if err != nil {
			return err
		}
	}
	time.Sleep(sleepDuration * time.Second)
	return nil
}

func addChallengeRecord(c cfdns.Client, domainName string, token string) error {
	zone := getZoneFromDomainName(domainName)
	zoneId, err := c.GetZoneIdByName(zone)
	if err != nil {
		return err
	}
	newRec, err := c.CreateDnsRecord(zoneId, "TXT", challengePrefix+domainName, token, nil, nil, nil)
	if err != nil {
		return err
	}
	if !newRec.Success {
		return fmt.Errorf("API error %s", newRec.Errors[0].Message)
	}
	return nil
}

func removeChallengeRecords(client cfdns.Client, args []string) error {
	argsPerDomain := 3
	for i := 0; i+2 < len(args); i += argsPerDomain {
		err := removeChallengeRecord(client, args[i])
		if err != nil {
			return err
		}
	}
	return nil
}

func removeChallengeRecord(c cfdns.Client, domainName string) error {
	zone := getZoneFromDomainName(domainName)
	zoneId, err := c.GetZoneIdByName(zone)
	if err != nil {
		return err
	}

	filter := cfdns.DnsRecordFilter{Type: "TXT", Name: challengePrefix + domainName}
	records, err := c.ListDnsRecords(zoneId, filter)
	if err != nil {
		return err
	}
	for _, record := range records.Records {
		c.DeleteDnsRecord(zoneId, record.Id)
	}
	return nil
}

func main() {
	var err error

	email := os.Getenv("CF_API_EMAIL")
	if len(email) == 0 {
		log.Fatalf("CF_API_EMAIL not set or empty.")
	}
	apiKey := os.Getenv("CF_API_KEY")
	if len(apiKey) == 0 {
		log.Fatalf("CF_API_KEY not set or empty.")
	}

	client := cfdns.NewClient(email, apiKey)

	operation := os.Args[1]
	params := os.Args[2:]

	switch operation {
	case "clean_challenge":
		err = removeChallengeRecords(client, params)
	case "deploy_challenge":
		err = addChallengeRecords(client, params)
	}
	if err != nil {
		log.Fatalf("Failed to execute %s, error %s", operation, err)
	}
}
