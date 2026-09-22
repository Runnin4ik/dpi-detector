// Command utlsdump writes the ClientHello a uTLS client profile puts on the
// wire, as hex, so the Rust harness can read it.
//
// It is a capture source and nothing else: it prints bytes, the library's own
// label for the profile and the byte count. Every measurement — JA3, JA4, the
// extension list, the padding length — happens in
// `cargo run --release --example tls_fingerprint -- hello <file>`, so a uTLS
// capture and a live browser capture are read by one implementation instead of
// two that can drift apart.
//
//	utlsdump list
//	utlsdump dump HelloChrome_133 [-sni example.com] [-seed <64 hex>] [-o capture.hex]
//
// The names are uTLS's own identifiers, not our profile names. `HelloChrome_133`
// is the library's spec and `chrome133` would be ours: the two are not the same
// hello, because uTLS leaves out extensions the wrapper sends and a browser
// shuffles what neither of them controls. What a capture proves is what a
// uTLS-based client sends — which is what the circumvention tools ship, and a
// different question from what a browser sends.
package main

import (
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"sort"
	"strings"

	utls "github.com/refraction-networking/utls"
)

// profiles are the library's exported ClientHelloIDs under the identifiers they
// are declared with, so a name here can be grepped in its `u_common.go`. A
// profile that disappears from the library stops compiling here, which is the
// point: the list is the library's, not a copy of it.
//
// `HelloCustom` is not here: it starts with an empty extension list and is meant
// to be filled by hand, so it has nothing of its own to dump — marshalling it
// fails the library's own length check.
var profiles = map[string]utls.ClientHelloID{
	"HelloGolang":           utls.HelloGolang,
	"HelloRandomized":       utls.HelloRandomized,
	"HelloRandomizedALPN":   utls.HelloRandomizedALPN,
	"HelloRandomizedNoALPN": utls.HelloRandomizedNoALPN,

	"HelloChrome_Auto":                 utls.HelloChrome_Auto,
	"HelloChrome_58":                   utls.HelloChrome_58,
	"HelloChrome_62":                   utls.HelloChrome_62,
	"HelloChrome_70":                   utls.HelloChrome_70,
	"HelloChrome_72":                   utls.HelloChrome_72,
	"HelloChrome_83":                   utls.HelloChrome_83,
	"HelloChrome_87":                   utls.HelloChrome_87,
	"HelloChrome_96":                   utls.HelloChrome_96,
	"HelloChrome_100":                  utls.HelloChrome_100,
	"HelloChrome_102":                  utls.HelloChrome_102,
	"HelloChrome_106_Shuffle":          utls.HelloChrome_106_Shuffle,
	"HelloChrome_100_PSK":              utls.HelloChrome_100_PSK,
	"HelloChrome_112_PSK_Shuf":         utls.HelloChrome_112_PSK_Shuf,
	"HelloChrome_114_Padding_PSK_Shuf": utls.HelloChrome_114_Padding_PSK_Shuf,
	"HelloChrome_115_PQ":               utls.HelloChrome_115_PQ,
	"HelloChrome_115_PQ_PSK":           utls.HelloChrome_115_PQ_PSK,
	"HelloChrome_120":                  utls.HelloChrome_120,
	"HelloChrome_120_PQ":               utls.HelloChrome_120_PQ,
	"HelloChrome_131":                  utls.HelloChrome_131,
	"HelloChrome_133":                  utls.HelloChrome_133,

	"HelloFirefox_Auto": utls.HelloFirefox_Auto,
	"HelloFirefox_55":   utls.HelloFirefox_55,
	"HelloFirefox_56":   utls.HelloFirefox_56,
	"HelloFirefox_63":   utls.HelloFirefox_63,
	"HelloFirefox_65":   utls.HelloFirefox_65,
	"HelloFirefox_99":   utls.HelloFirefox_99,
	"HelloFirefox_102":  utls.HelloFirefox_102,
	"HelloFirefox_105":  utls.HelloFirefox_105,
	"HelloFirefox_120":  utls.HelloFirefox_120,

	"HelloIOS_Auto": utls.HelloIOS_Auto,
	"HelloIOS_11_1": utls.HelloIOS_11_1,
	"HelloIOS_12_1": utls.HelloIOS_12_1,
	"HelloIOS_13":   utls.HelloIOS_13,
	"HelloIOS_14":   utls.HelloIOS_14,

	"HelloAndroid_11_OkHttp": utls.HelloAndroid_11_OkHttp,

	"HelloEdge_Auto": utls.HelloEdge_Auto,
	"HelloEdge_85":   utls.HelloEdge_85,
	"HelloEdge_106":  utls.HelloEdge_106,

	"HelloSafari_Auto": utls.HelloSafari_Auto,
	"HelloSafari_16_0": utls.HelloSafari_16_0,

	"Hello360_Auto": utls.Hello360_Auto,
	"Hello360_7_5":  utls.Hello360_7_5,
	"Hello360_11_0": utls.Hello360_11_0,

	"HelloQQ_Auto": utls.HelloQQ_Auto,
	"HelloQQ_11_1": utls.HelloQQ_11_1,
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "list":
		list(os.Stdout)
	case "dump":
		err = dump(os.Args[2:], os.Stdout)
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "utlsdump: %v\n", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `utlsdump writes the ClientHello of a uTLS client profile as hex.

	utlsdump list
	utlsdump dump <profile> [-sni example.com] [-seed <64 hex>] [-o capture.hex]

The hex is read back by
	cargo run --release --example tls_fingerprint -- hello capture.hex
which prints its JA3, JA4 and extension list. A bare handshake message is
accepted there too, but this tool emits the whole TLS record — what a listener
would capture — so the file can be diffed against a real one.
`)
}

// list prints the profiles the library ships, in the spelling the tool takes.
func list(w io.Writer) {
	names := make([]string, 0, len(profiles))
	width := 0
	for name := range profiles {
		names = append(names, name)
		if len(name) > width {
			width = len(name)
		}
	}
	sort.Strings(names)
	for _, name := range names {
		id := profiles[name]
		fmt.Fprintf(w, "%-*s  %s\n", width, name, id.Str())
	}
}

// dump writes one profile's first flight. `-seed` only affects the randomized
// profiles, whose spec is drawn from a PRNG: fixing it makes the capture
// reproducible, which is why the seed is echoed in the header line.
func dump(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("dump", flag.ExitOnError)
	sni := fs.String("sni", "example.com", "SNI to offer; an empty value omits the extension")
	seed := fs.String("seed", "", "hex seed for a HelloRandomized* profile (32 bytes)")
	out := fs.String("o", "", "write the hex to this file instead of stdout")
	// `dump <profile> [-flags]` and `dump [-flags] <profile>` both work: the
	// stdlib parser stops at the first non-flag argument, so a profile in front
	// has to be split off before the flags are read.
	var name string
	flagArgs := args
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		name, flagArgs = args[0], args[1:]
	}
	if err := fs.Parse(flagArgs); err != nil {
		return err
	}
	switch {
	case name != "" && fs.NArg() != 0:
		return errors.New("dump takes exactly one profile name; run `utlsdump list`")
	case name == "" && fs.NArg() == 1:
		name = fs.Arg(0)
	case name == "":
		return errors.New("dump takes exactly one profile name; run `utlsdump list`")
	}
	id, ok := profiles[name]
	if !ok {
		return fmt.Errorf("unknown profile %q; run `utlsdump list`", name)
	}
	if *seed != "" {
		raw, err := hex.DecodeString(*seed)
		if err != nil {
			return fmt.Errorf("seed: %w", err)
		}
		var s utls.PRNGSeed
		if len(raw) != len(s) {
			return fmt.Errorf("seed must be %d bytes, got %d", len(s), len(raw))
		}
		copy(s[:], raw)
		id.Seed = &s
	}

	record, err := helloRecord(&id, *sni)
	if err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}

	w := stdout
	if *out != "" {
		f, err := os.Create(*out)
		if err != nil {
			return err
		}
		defer f.Close()
		w = f
	}
	return writeHex(w, name, &id, *sni, *seed, record)
}

// The record header a listener would have captured the hello under: the
// handshake content type, and the TLS 1.0 record version every client still
// opens with.
const (
	recordTypeHandshake = 0x16
	recordVersionTLS10  = 0x0301
)

// helloRecord builds the profile's first flight. The library marshals the
// handshake message into `HandshakeState.Hello.Raw` — type, three-byte length,
// body — and it is written out under the record header a listener would have
// captured it with, so the file is what went on the wire and not a step short of
// it. The pipe exists only because the constructor wants a connection, and
// nothing is ever written to it.
func helloRecord(id *utls.ClientHelloID, sni string) ([]byte, error) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	uconn := utls.UClient(client, &utls.Config{ServerName: sni}, *id)
	if err := uconn.BuildHandshakeState(); err != nil {
		return nil, fmt.Errorf("building the hello: %w", err)
	}
	if err := uconn.MarshalClientHello(); err != nil {
		return nil, fmt.Errorf("marshalling the hello: %w", err)
	}
	message := uconn.HandshakeState.Hello.Raw
	if len(message) == 0 {
		return nil, errors.New("the library marshalled an empty hello")
	}
	if len(message) > 0xffff {
		return nil, fmt.Errorf("the hello is %d bytes, longer than one record", len(message))
	}
	if message[0] == recordTypeHandshake {
		return message, nil
	}
	record := make([]byte, 5, len(message)+5)
	record[0] = recordTypeHandshake
	record[1], record[2] = recordVersionTLS10>>8, recordVersionTLS10&0xff
	record[3], record[4] = byte(len(message)>>8), byte(len(message))
	return append(record, message...), nil
}

// writeHex prints the record as a header line and 32-byte rows. Both the header
// (a `#` comment) and the row breaks are ignored by the harness's decoder, so
// the file can be read as it is.
func writeHex(w io.Writer, name string, id *utls.ClientHelloID, sni, seed string, record []byte) error {
	parts := []string{fmt.Sprintf("uTLS %s (%s)", name, id.Str())}
	if sni == "" {
		parts = append(parts, "SNI none")
	} else {
		parts = append(parts, "SNI "+sni)
	}
	parts = append(parts, fmt.Sprintf("%d bytes, %d-byte hello", len(record), len(record)-5))
	if seed != "" {
		parts = append(parts, "seed "+seed)
	}
	if _, err := fmt.Fprintf(w, "# %s\n", strings.Join(parts, ", ")); err != nil {
		return err
	}
	const perRow = 32
	for i := 0; i < len(record); i += perRow {
		end := min(i+perRow, len(record))
		if _, err := fmt.Fprintf(w, "%s\n", hex.EncodeToString(record[i:end])); err != nil {
			return err
		}
	}
	return nil
}
