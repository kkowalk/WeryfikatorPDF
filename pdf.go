package main

import (
	"bytes"
	"compress/zlib"
	"encoding/hex"
	"io"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// pdfSig is one signature (or document timestamp) found via its /ByteRange.
type pdfSig struct {
	ByteRange [4]int64
	DER       []byte    // CMS from /Contents (may carry trailing zero padding)
	SubFilter string    // e.g. ETSI.CAdES.detached, ETSI.RFC3161
	M         time.Time // /M from the signature dictionary (zero if absent)
	Signed    []byte    // bytes covered by the signature
	End       int64     // offset where the signed revision ends
}

var (
	reByteRange = regexp.MustCompile(`/ByteRange\s*\[\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*\]`)
	reSubFilter = regexp.MustCompile(`/SubFilter\s*/([A-Za-z0-9.#_-]+)`)
	reM         = regexp.MustCompile(`/M\s*\((D:[^)]*)\)`)
)

// findSignatures scans raw PDF bytes. The /Contents hex string of a signature
// is by definition the literal gap between ByteRange segments, so no PDF
// object parser is needed.
// ponytail: no xref/DocMDP analysis; changes after signing are reported by byte range only.
func findSignatures(data []byte) []pdfSig {
	n := int64(len(data))
	seen := map[[4]int64]bool{}
	var out []pdfSig
	for _, m := range reByteRange.FindAllSubmatchIndex(data, -1) {
		var br [4]int64
		for i := range br {
			br[i], _ = strconv.ParseInt(string(data[m[2+2*i]:m[3+2*i]]), 10, 64)
		}
		a, b, c, d := br[0], br[1], br[2], br[3]
		if seen[br] || a != 0 || b < 2 || c <= b+1 || d < 0 || c+d > n || data[b] != '<' || data[c-1] != '>' {
			continue
		}
		seen[br] = true
		der, err := hex.DecodeString(string(bytes.Join(bytes.Fields(data[b+1:c-1]), nil)))
		if err != nil {
			continue
		}
		s := pdfSig{ByteRange: br, DER: der, End: c + d}
		s.Signed = append(append([]byte{}, data[:b]...), data[c:c+d]...)

		// Signature dictionary text around the gap, without the hex blob.
		var dict []byte
		if lo := bytes.LastIndex(data[:min(int64(m[0]), b)], []byte("obj")); lo >= 0 {
			dict = append(dict, data[lo:b]...)
		}
		from := max(int64(m[1]), c)
		if hi := bytes.Index(data[from:], []byte("endobj")); hi >= 0 {
			dict = append(dict, data[c:from+int64(hi)]...)
		}
		if mm := reSubFilter.FindSubmatch(dict); mm != nil {
			s.SubFilter = string(mm[1])
		}
		if mm := reM.FindSubmatch(dict); mm != nil {
			s.M, _ = parsePDFDate(string(mm[1]))
		}
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].End < out[j].End })
	return out
}

// parsePDFDate parses D:YYYYMMDDHHmmSS[Z|+HH'mm'].
func parsePDFDate(s string) (time.Time, bool) {
	s = strings.TrimPrefix(s, "D:")
	i := 0
	for i < len(s) && i < 14 && s[i] >= '0' && s[i] <= '9' {
		i++
	}
	if i < 4 || i%2 != 0 {
		return time.Time{}, false
	}
	t, err := time.Parse("20060102150405"[:i], s[:i])
	if err != nil {
		return time.Time{}, false
	}
	rest := s[i:]
	if len(rest) >= 3 && (rest[0] == '+' || rest[0] == '-') {
		h, _ := strconv.Atoi(rest[1:3])
		mi := 0
		if len(rest) >= 6 && rest[3] == '\'' {
			mi, _ = strconv.Atoi(rest[4:6])
		}
		off := time.Duration(h*60+mi) * time.Minute
		if rest[0] == '-' {
			off = -off
		}
		t = t.Add(-off)
	}
	return t, true
}

// harvestStreams looks into every PDF stream for DER certificates, CRLs and
// OCSP responses (the /DSS dictionary of PAdES-LT stores them as streams).
// Anything found is only a candidate: it is used only if its signature verifies.
func (p *pool) harvestStreams(data []byte) {
	for i := 0; ; {
		k := bytes.Index(data[i:], []byte("stream"))
		if k < 0 {
			return
		}
		pos := i + k
		i = pos + 6
		if pos >= 3 && string(data[pos-3:pos]) == "end" {
			continue
		}
		start := i
		if start < len(data) && data[start] == '\r' {
			start++
		}
		if start < len(data) && data[start] == '\n' {
			start++
		}
		end := bytes.Index(data[start:], []byte("endstream"))
		if end < 0 {
			return
		}
		p.tryStream(data[start : start+end])
		i = start + end + 9
	}
}

func (p *pool) tryStream(b []byte) {
	if len(b) > 0 && b[0] == 0x30 {
		p.harvest(b, 0)
		return
	}
	if len(b) < 2 || b[0] != 0x78 { // not zlib
		return
	}
	zr, err := zlib.NewReader(bytes.NewReader(b))
	if err != nil {
		return
	}
	head := make([]byte, 1)
	if _, err := io.ReadFull(zr, head); err != nil || head[0] != 0x30 {
		return // not DER: images, fonts, content streams
	}
	rest, _ := io.ReadAll(io.LimitReader(zr, 50<<20))
	p.harvest(append(head, rest...), 0)
}
