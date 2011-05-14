/*
 * mysql-sniffer.go
 *
 * A straightforward program for sniffing MySQL query streams and providing
 * diagnostic information on the realtime queries your database is handling.
 *
 * FIXME: this assumes IPv4.
 * FIXME: tokenizer doesn't handle negative numbers or floating points.
 * FIXME: canonicalizer should collapse "IN (?,?,?,?)" and "VALUES (?,?,?,?)"
 * FIXME: tokenizer breaks on '"' or similarly embedded quotes
 * FIXME: canonicalizer doesn't strip newlines or collapse space
 * FIXME: tokenizer parses numbers in words wrong, i.e. s2compiled -> s?compiled
 *
 * written by Mark Smith <mark@qq.is>
 *
 * requires the gopcap library to be installed from:
 *   https://github.com/xb95/gopcap
 *
 */

package main

import (
	"flag"
	"fmt"
	"log"
	"pcap"
	"sort"
	"strings"
	"time"
)

var start int64 = time.Seconds()
var qbuf map[string]int = make(map[string]int)
var querycount int

const TOKEN_DEFAULT = 0
const TOKEN_QUOTE = 1
const TOKEN_NUMBER = 2

func main() {
	var port *int = flag.Int("P", 3306, "MySQL port to use")
	var eth *string = flag.String("i", "eth0", "Interface to sniff")
	var snaplen *int = flag.Int("s", 1024, "Bytes of each packet to sniff")
	var dirty *bool = flag.Bool("u", false, "Unsanitized -- do not canonicalize queries")
	var binary *bool = flag.Bool("b", false, "Output binary -- do not escape binary in queries")
	var period *int = flag.Int("t", 10, "Seconds between outputting status")
	var displaycount *int = flag.Int("d", 25, "Display this many queries in status updates")
	var verbose *bool = flag.Bool("v", false, "Print every query received (spammy)")
	flag.Parse()

	log.SetPrefix("")
	log.SetFlags(0)

	log.Printf("Initializing MySQL sniffing on %s:%d...", *eth, *port)
	iface, err := pcap.Openlive(*eth, int32(*snaplen), false, 0)
	if iface == nil || err != "" {
		if err == "" {
			err = "unknown error"
		}
		log.Fatalf("Failed to open device: %s", err)
	}

	err = iface.Setfilter(fmt.Sprintf("tcp dst port %d", *port))
	if err != "" {
		log.Fatalf("Failed to set port filter: %s", err)
	}

	last := time.Seconds()
	var pkt *pcap.Packet = nil
	var rv int32 = 0

	for rv = 0; rv >= 0; {
		for pkt, rv = iface.NextEx(); pkt != nil; pkt, rv = iface.NextEx() {
			handlePacket(pkt, *dirty, *binary, *verbose)

			// simple output printer... this should be super fast since we expect that a
			// system like this will have relatively few unique queries once they're
			// canonicalized.
			if !*verbose && querycount%100 == 0 && last < time.Seconds()-int64(*period) {
				last = time.Seconds()
				handleStatusUpdate(*displaycount)
			}
		}
	}
}

func handleStatusUpdate(displaycount int) {
	elapsed := float64(time.Seconds() - start)

	// print status bar
	log.Printf("\n")
	log.SetFlags(log.Ldate | log.Ltime)
	log.Printf("%d total queries, %0.2f per second", querycount, float64(querycount)/elapsed)
	log.SetFlags(0)

	// we cheat so badly here...
	var tmp sort.StringArray = make([]string, 0, len(qbuf))
	for q, c := range qbuf {
		tmp = append(tmp, fmt.Sprintf("%6d  %0.2f/s  %s", c, float64(c)/elapsed, q))
	}
	sort.Sort(tmp)

	// now print top to bottom, since our sorted list is sorted backwards
	// from what we want
	if len(tmp) < displaycount {
		displaycount = len(tmp)
	}
	for i := 1; i <= displaycount; i++ {
		log.Printf(tmp[len(tmp)-i])
	}
}

// extract the data... we have to figure out where it is, which means extracting data
// from the various headers until we get the location we want.  this is crude, but
// functional and it should be fast.
func handlePacket(pkt *pcap.Packet, dirty, binary, verbose bool) {
	// Ethernet frame has 14 bytes of stuff to ignore, so we start our root position here
	var pos uint8 = 14

	// The IP frame has the header length in bits 4-7 of byte 0 (relative)
	pos += pkt.Data[pos] & 0x0F * 4

	// The TCP frame has the data offset in bits 4-7 of byte 12 (relative)
	pos += uint8(pkt.Data[pos+12]) >> 4 * 4

	// must be at least 6 bytes of payload
	if len(pkt.Data)-int(pos) <= 6 {
		return
	}

	// MySQL packet type is the fifth byte... COM_QUERY is 0x03, if it's not that
	// then we don't care, move on
	if pkt.Data[pos+4] != 0x03 {
		return
	}

	// the query is now in query ... easier to deal with than always offsetting
	handleQuery(pkt.Data[pos+5:], dirty, binary, verbose)
}

// scans forward in the query given the current type and returns when we encounter
// a new type and need to stop scanning.  returns the size of the last token and
// the type of it.
func scanToken(query []byte) (length int, thistype int) {
	if len(query) < 1 {
		log.Fatalf("scanToken called with empty query")
	}

	// peek at the first byte, then loop
	switch {
	case query[0] == 39 || query[0] == 34: // '"
		escaped := false
		for i := 1; i < len(query); i++ {
			switch query[i] {
			case 39, 34:
				if escaped {
					escaped = false
					continue
				}
				return i, TOKEN_QUOTE
			case 92:
				escaped = true
			default:
				escaped = false
			}
		}
		return len(query), TOKEN_QUOTE

	case query[0] >= 48 && query[0] <= 57: // 0-9
		for i := 1; i < len(query); i++ {
			switch {
			case query[i] >= 48 && query[i] <= 57: // 0-9
			default:
				return i, TOKEN_NUMBER
			}
		}
		return len(query), TOKEN_NUMBER

	default:
		for i := 1; i < len(query); i++ {
			switch {
			case query[i] == 39 || query[i] == 34 || (query[i] >= 48 && query[i] <= 57):
				return i, TOKEN_DEFAULT
			default:
			}
		}
		return len(query), TOKEN_DEFAULT
	}

	// shouldn't get here
	log.Fatalf("scanToken failure: [%s]", query)
	return
}

func cleanupRawQuery(query []byte) string {
	var qspace []string
	var theByte byte
	for i := 0; i < len(query); i++ {
		theByte = query[i]
		if (theByte >= 0x20 && theByte <= 0x7E) || theByte == 0x0A || theByte == 0x0D {
			qspace = append(qspace, string(theByte))
		} else {
			qspace = append(qspace, fmt.Sprintf("\\x%02x", theByte))
		}
	}
	return strings.Join(qspace, "")
}

func cleanupQuery(query []byte) string {
	// iterate until we hit the end of the query...
	var qspace []string
	for i := 0; i < len(query); {
		length, toktype := scanToken(query[i:])

		switch toktype {
		case TOKEN_DEFAULT:
			qspace = append(qspace, string(query[i:i+length]))

		case TOKEN_NUMBER, TOKEN_QUOTE:
			qspace = append(qspace, "?")

		default:
			log.Fatalf("scanToken returned invalid token type %d", toktype)
		}

		i += length
	}

	// store in our global structure
	return strings.Join(qspace, "")
}

func handleQuery(query []byte, dirty bool, binary bool, verbose bool) {
	var qstr string
	if dirty && binary {
		qstr = string(query)
	} else if dirty {
		qstr = cleanupRawQuery(query)
	} else {
		qstr = cleanupQuery(query)
	}

	// if verbose, just print it
	if verbose {
		log.Print(qstr)
		return
	}

	// map for later...
	querycount++
	qbuf[qstr]++
}
