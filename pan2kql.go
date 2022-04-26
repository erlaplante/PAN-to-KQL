// PAN-to-KQL

package main

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/atotto/clipboard"
)

// accepts PST datetime string used by PAN filter and returns it as a UTC datetime string
func convertToUtc(datetime_str string) string {
	layout := "2006/01/02 15:04:05"
	pst, _ := time.LoadLocation("America/Los_Angeles")
	utc, _ := time.LoadLocation("UTC")

	datetime, _ := time.ParseInLocation(layout, datetime_str, pst)
	datetimeUtc := datetime.In(utc)
	return datetimeUtc.Format("2006-01-02 15:04:05")
}

func main() {

	translation := map[string]string{
		" eq ":                " == ",
		" in ":                " == ",
		" neq ":               " != ",
		" notin ":             " != ",
		"rule ":               "Rule ",
		"action ":             "DeviceAction ",
		"addr.src ":           "SourceIP ",
		"addr.dst ":           "DestinationIP ",
		"port.src ":           "SourcePort ",
		"port.dst ":           "DestinationPort ",
		"user.src ":           "SourceUserName ",
		"zone.src ":           "SourceZone ",
		"zone.dst ":           "DestinationZone ",
		"session_end_reason ": "reason ",
		"proto ":              "Protocol ",
		"app ":                "ApplicationProtocol ",
		"subtype ":            "DeviceEventClassID ",
		"natsrc ":             "SourceTranslatedAddress ",
		"natdst ":             "DestinationTranslatedAddress ",
		"device_name ":        "DeviceName ",
	}

	fmt.Print("Enter PAN filter to translate:\n  ")
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Scan()
	query := scanner.Text()

	// check for time conversion and validate format
	if strings.Contains(query, "time_generated") || strings.Contains(query, "receive_time") {
		timeBtwnRegex := regexp.MustCompile(`\(\s*(?:time_generated|receive_time) geq \'(\d\d\d\d\/\d\d\/\d\d \d\d:\d\d:\d\d)\'.*\)\s+and\s+\(.*(?:time_generated|receive_time) leq \'(\d\d\d\d\/\d\d\/\d\d \d\d:\d\d:\d\d)\'\s*\)`)
		sm_timeBtwnRegex := timeBtwnRegex.FindStringSubmatch(query)

		incorrectTimeMsg := "Incorrect PAN time format\n\nMust use \"( time_generated geq 'YYYY/MM/DD hh:mm:ss' ) and ( time_generated leq 'YYYY/MM/DD hh:mm:ss' )\" in this order to search between times.\nOr a single \"time_generated geq <OR> leq\", \"receive_time\" is also accepted, both translated to \"TimeGenerated\"."

		// submatch has "greater than or equal" and "less than or equal" datetimes in PAN filter in correct order
		// assign both variables and do UTC conversion
		if len(sm_timeBtwnRegex) != 0 {
			geqDateStr := sm_timeBtwnRegex[1]
			leqDateStr := sm_timeBtwnRegex[2]

			geqUtcStr := convertToUtc(geqDateStr)
			leqUtcStr := convertToUtc(leqDateStr)

			query = timeBtwnRegex.ReplaceAllString(query, "TimeGenerated between(datetime('"+geqUtcStr+"') .. datetime('"+leqUtcStr+"'))")
		} else {
			// check for single datetime in filter/query
			singularCheckRegex := regexp.MustCompile(`(time_generated|receive_time)`)
			matches := singularCheckRegex.FindAllString(query, -1)
			if len(matches) > 1 {
				fmt.Println(incorrectTimeMsg)
				os.Exit(1)
			} else {
				singularTimeRegex := regexp.MustCompile(`(?:time_generated|receive_time) ([gl]eq) \'(\d\d\d\d\/\d\d\/\d\d \d\d:\d\d:\d\d)\'`)
				sm_singularTimeRegex := singularTimeRegex.FindStringSubmatch(query)

				// single datetime in correct PAN format
				if len(sm_singularTimeRegex) != 0 {
					equality := sm_singularTimeRegex[1]
					singleDateStr := sm_singularTimeRegex[2]

					if equality == "geq" {
						equality = ">="
					} else {
						equality = "<="
					}
					singleUtcStr := convertToUtc(singleDateStr)
					query = singularTimeRegex.ReplaceAllString(query, "TimeGenerated "+equality+" todatetime('"+singleUtcStr+"')")
				} else {
					fmt.Println(incorrectTimeMsg)
					os.Exit(1)
				}
			}
		}
	}

	// swap each key with element from translation map
	for key := range translation {
		if strings.Contains(query, key) {
			query = strings.Replace(query, key, translation[key], -1)
		}
	}

	// translate PAN "addr (not)in" to use Source or Destination IP in KQL,
	// "addQuotes" regex looks for ending ")" so in this case adds in single quotes around SourceIP
	addrin := regexp.MustCompile(`addr (==|!=) (\'?(\d{1,3}\.){3}\d{1,3}(?:\/\d{1,2})?\'?)`)
	sm_addrin := addrin.FindStringSubmatch(query)
	if len(sm_addrin) != 0 {
		if sm_addrin[1] == "==" {
			query = addrin.ReplaceAllString(query, "SourceIP ${1} '${2}' or DestinationIP ${1} ${2}")
		} else {
			query = addrin.ReplaceAllString(query, "not(SourceIP == '${2}' or DestinationIP == ${2})")
		}
	}

	// add single quotes around KQL declaration
	addQuotes := regexp.MustCompile(`([!=]= )([^ \)]+)( ?\))`)
	query = addQuotes.ReplaceAllString(query, "${1}'${2}'${3}")

    // remove quotes around Port (integer)
    removePortQuotes := regexp.MustCompile(`(Port [!=]= )'(\d+)'`)
    query = removePortQuotes.ReplaceAllString(query, "${1}${2}")

	// cleanup potential consecutive single quotes
	query = strings.Replace(query, "''", "'", -1)

	// add "@" to use verbatim string literal in down-level logon name (Domain\SAMAccountName)
	strLiteral := regexp.MustCompile(`('\w+\\)([\w\.]+')`)
	query = strLiteral.ReplaceAllString(query, "@${1}\\${2}")

	// CIDR translation
	cidr := regexp.MustCompile(`(not\()?(SourceIP|DestinationIP) ([!=]=) ('(\d{1,3}\.){3}\d{1,3}\/\d{1,2}')`)
	sm_cidr := cidr.FindStringSubmatch(query)
	if len(sm_cidr) != 0 {
		if sm_cidr[3] == "!=" {
			query = cidr.ReplaceAllString(query, "not(ipv4_is_match(${2}, ${4}))")
		} else {
			query = cidr.ReplaceAllString(query, "${1}ipv4_is_match(${2}, ${4})")
		}
	}

	clipboard.WriteAll(query)
	fmt.Print("\nTranslation (copied to clipboard):\n  " + query)
}
