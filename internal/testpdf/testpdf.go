// Package testpdf writes small PDF files for the pdftext tests and benchmarks.
//
// It is a deliberately minimal writer: objects are appended as raw PDF syntax,
// Bytes writes the header, the objects, a classic cross-reference table and
// the trailer. Nothing here is a general purpose PDF library; it exists so
// that the test fixtures are generated in code instead of being checked in
// as binary files.
package testpdf

import (
	"bytes"
	"compress/zlib"
	"crypto/md5"
	"crypto/rc4"
	"encoding/binary"
	"fmt"
	"strings"
	"unicode/utf16"
)

// Builder accumulates numbered objects. Object numbers start at 1 and are
// handed out in the order of the Add calls.
type Builder struct {
	objs    []object
	Encrypt *Encryption // When set, streams and string literals are RC4-encrypted (standard security handler R2).
}

type object struct {
	dict   string // Dictionary or scalar body; for streams the stream dictionary without /Length.
	stream []byte // Stream data, nil for non-stream objects.
	isStr  bool
}

// Encryption describes the standard security handler, revision 2 (RC4 40
// bit). UserPassword non-empty makes the document unopenable without it.
type Encryption struct {
	UserPassword  string
	OwnerPassword string
}

// Add appends an object whose body is the given PDF syntax and returns its
// object number.
func (b *Builder) Add(body string) int {
	b.objs = append(b.objs, object{dict: body})
	return len(b.objs)
}

// Reserve returns the next object number without defining it; Set defines it
// later. Useful for objects that reference each other.
func (b *Builder) Reserve() int {
	b.objs = append(b.objs, object{})
	return len(b.objs)
}

// Set defines a reserved object.
func (b *Builder) Set(num int, body string) {
	b.objs[num-1] = object{dict: body}
}

// AddStream appends a stream object. dict is the stream dictionary without
// the /Length entry and without the closing >>, e.g. "<< /Filter /FlateDecode".
func (b *Builder) AddStream(dict string, data []byte) int {
	b.objs = append(b.objs, object{dict: dict, stream: data, isStr: true})
	return len(b.objs)
}

// SetStream defines a reserved object as a stream.
func (b *Builder) SetStream(num int, dict string, data []byte) {
	b.objs[num-1] = object{dict: dict, stream: data, isStr: true}
}

// Bytes serialises the file. root is the object number of the catalog and
// extraTrailer is appended inside the trailer dictionary (may be empty).
func (b *Builder) Bytes(root int, extraTrailer string) []byte {
	var out bytes.Buffer
	out.WriteString("%PDF-1.7\n%\xe2\xe3\xcf\xd3\n")

	var enc *encState
	var fileID []byte
	if b.Encrypt != nil {
		fileID = bytes.Repeat([]byte{0xAB}, 16)
		enc = newEncState(b.Encrypt, fileID)
	}
	var encObj int
	if enc != nil {
		encObj = b.Add(fmt.Sprintf("<< /Filter /Standard /V 1 /R 2 /Length 40 /P -1 /O <%x> /U <%x> >>", enc.o, enc.u))
	}

	offsets := make([]int, len(b.objs)+1)
	for i, o := range b.objs {
		num := i + 1
		offsets[num] = out.Len()
		fmt.Fprintf(&out, "%d 0 obj\n", num)
		if o.isStr {
			data := o.stream
			if enc != nil && num != encObj {
				data = enc.crypt(num, data)
			}
			fmt.Fprintf(&out, "%s /Length %d >>\nstream\n", o.dict, len(data))
			out.Write(data)
			out.WriteString("\nendstream\n")
		} else {
			out.WriteString(o.dict)
			out.WriteString("\n")
		}
		out.WriteString("endobj\n")
	}

	xref := out.Len()
	fmt.Fprintf(&out, "xref\n0 %d\n", len(b.objs)+1)
	out.WriteString("0000000000 65535 f \n")
	for num := 1; num <= len(b.objs); num++ {
		fmt.Fprintf(&out, "%010d 00000 n \n", offsets[num])
	}
	fmt.Fprintf(&out, "trailer\n<< /Size %d /Root %d 0 R", len(b.objs)+1, root)
	if enc != nil {
		fmt.Fprintf(&out, " /Encrypt %d 0 R /ID [<%x> <%x>]", encObj, fileID, fileID)
	}
	if extraTrailer != "" {
		out.WriteString(" ")
		out.WriteString(extraTrailer)
	}
	fmt.Fprintf(&out, " >>\nstartxref\n%d\n%%%%EOF\n", xref)
	return out.Bytes()
}

// Flate compresses data with zlib (the PDF FlateDecode filter).
func Flate(data []byte) []byte {
	var buf bytes.Buffer
	w, _ := zlib.NewWriterLevel(&buf, zlib.BestCompression)
	w.Write(data)
	w.Close()
	return buf.Bytes()
}

// FlateRepeat compresses n copies of c without holding them in memory,
// for decompression-bomb fixtures.
func FlateRepeat(c byte, n int) []byte {
	var buf bytes.Buffer
	w, _ := zlib.NewWriterLevel(&buf, zlib.BestCompression)
	chunk := bytes.Repeat([]byte{c}, 1<<20)
	for n > 0 {
		k := min(n, len(chunk))
		w.Write(chunk[:k])
		n -= k
	}
	w.Close()
	return buf.Bytes()
}

// Literal escapes s as a PDF literal string, including the parentheses.
func Literal(s string) string {
	var sb strings.Builder
	sb.WriteByte('(')
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch c {
		case '(', ')', '\\':
			sb.WriteByte('\\')
			sb.WriteByte(c)
		case '\r':
			sb.WriteString(`\r`)
		case '\n':
			sb.WriteString(`\n`)
		default:
			if c < 0x20 || c > 0x7e {
				fmt.Fprintf(&sb, `\%03o`, c)
			} else {
				sb.WriteByte(c)
			}
		}
	}
	sb.WriteByte(')')
	return sb.String()
}

// TextString encodes s as a PDF text string (UTF-16BE with BOM, as a hex
// string), which carries any Unicode in annotation contents and form values.
func TextString(s string) string {
	var sb strings.Builder
	sb.WriteString("<FEFF")
	for _, u := range utf16.Encode([]rune(s)) {
		fmt.Fprintf(&sb, "%04X", u)
	}
	sb.WriteString(">")
	return sb.String()
}

// Page describes one page of a Document.
type Page struct {
	Content   string   // Content stream (uncompressed unless Compress is set).
	Compress  bool     // Compress the content stream with FlateDecode.
	Annots    []string // Annotation dictionaries; "%PAGE%" inside is replaced by the page reference.
	XObjects  string   // Extra entries for /Resources /XObject, e.g. "/Im1 7 0 R".
	Width     float64  // Media box width in points; 0 means 612.
	Height    float64  // Media box height in points; 0 means 792.
	RawStream []byte   // When set, used verbatim as the content stream data instead of Content.
	RawDict   string   // Extra entries for the content stream dictionary, e.g. "/Filter [/FlateDecode /FlateDecode]".
}

// Document describes a whole test file.
type Document struct {
	Pages     []Page
	Unicode   *UnicodeFont // When set, resource /F2 is a Type0 font with this ToUnicode map.
	Fields    []string     // Field dictionaries for the AcroForm (object bodies); "%PAGE%" is replaced by the first page.
	Catalog   string       // Extra catalog entries.
	Encrypt   *Encryption
	Trailer   string // Extra trailer entries.
	Objects   []string
	ObjectsFn func(b *Builder) // Hook to add arbitrary objects before the pages are written.
}

// UnicodeFont is a Type0 font whose two-byte codes map to the given runes
// through a ToUnicode CMap. Code 1 maps to Runes[0], code 2 to Runes[1], etc.
type UnicodeFont struct {
	Runes []rune
}

// Encode turns s into the hex string operand of Tj for the UnicodeFont.
func (f *UnicodeFont) Encode(s string) string {
	idx := map[rune]int{}
	for i, r := range f.Runes {
		idx[r] = i + 1
	}
	var sb strings.Builder
	sb.WriteByte('<')
	for _, r := range s {
		code, ok := idx[r]
		if !ok {
			panic(fmt.Sprintf("testpdf: rune %q is not in the font", r))
		}
		fmt.Fprintf(&sb, "%04X", code)
	}
	sb.WriteByte('>')
	return sb.String()
}

func (f *UnicodeFont) cmap() string {
	var sb strings.Builder
	sb.WriteString("/CIDInit /ProcSet findresource begin\n12 dict begin\nbegincmap\n")
	sb.WriteString("/CIDSystemInfo << /Registry (Adobe) /Ordering (UCS) /Supplement 0 >> def\n")
	sb.WriteString("/CMapName /Adobe-Identity-UCS def\n/CMapType 2 def\n")
	sb.WriteString("1 begincodespacerange\n<0000> <FFFF>\nendcodespacerange\n")
	fmt.Fprintf(&sb, "%d beginbfchar\n", len(f.Runes))
	for i, r := range f.Runes {
		fmt.Fprintf(&sb, "<%04X> <", i+1)
		for _, u := range utf16.Encode([]rune{r}) {
			fmt.Fprintf(&sb, "%04X", u)
		}
		sb.WriteString(">\n")
	}
	sb.WriteString("endbfchar\nendcmap\nCMapName currentdict /CMap defineresource pop\nend\nend\n")
	return sb.String()
}

// Build serialises the document.
func Build(d Document) []byte {
	b := &Builder{Encrypt: d.Encrypt}
	catalog := b.Reserve()
	pages := b.Reserve()
	helv := b.Add("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>")

	fonts := fmt.Sprintf("/F1 %d 0 R", helv)
	if d.Unicode != nil {
		desc := b.Add("<< /Type /FontDescriptor /FontName /Helvetica /Flags 32 /FontBBox [0 -200 1000 900] /ItalicAngle 0 /Ascent 900 /Descent -200 /CapHeight 700 /StemV 80 >>")
		cid := b.Add(fmt.Sprintf("<< /Type /Font /Subtype /CIDFontType2 /BaseFont /Helvetica /CIDSystemInfo << /Registry (Adobe) /Ordering (Identity) /Supplement 0 >> /FontDescriptor %d 0 R /DW 600 >>", desc))
		tu := b.AddStream("<<", []byte(d.Unicode.cmap()))
		f2 := b.Add(fmt.Sprintf("<< /Type /Font /Subtype /Type0 /BaseFont /Helvetica /Encoding /Identity-H /DescendantFonts [%d 0 R] /ToUnicode %d 0 R >>", cid, tu))
		fonts += fmt.Sprintf(" /F2 %d 0 R", f2)
	}

	if d.ObjectsFn != nil {
		d.ObjectsFn(b)
	}
	for _, o := range d.Objects {
		b.Add(o)
	}

	var kids []string
	var pageNums []int
	for range d.Pages {
		pageNums = append(pageNums, b.Reserve())
	}
	var fieldRefs []string
	firstPage := 0
	if len(pageNums) > 0 {
		firstPage = pageNums[0]
	}
	for _, fd := range d.Fields {
		n := b.Add(strings.ReplaceAll(fd, "%PAGE%", fmt.Sprintf("%d 0 R", firstPage)))
		fieldRefs = append(fieldRefs, fmt.Sprintf("%d 0 R", n))
	}

	for i, p := range d.Pages {
		num := pageNums[i]
		pageRef := fmt.Sprintf("%d 0 R", num)
		var content int
		switch {
		case p.RawStream != nil:
			content = b.AddStream("<< "+p.RawDict, p.RawStream)
		case p.Compress:
			content = b.AddStream("<< /Filter /FlateDecode", Flate([]byte(p.Content)))
		default:
			content = b.AddStream("<<", []byte(p.Content))
		}
		var annots []string
		for _, a := range p.Annots {
			n := b.Add(strings.ReplaceAll(a, "%PAGE%", pageRef))
			annots = append(annots, fmt.Sprintf("%d 0 R", n))
		}
		if i == 0 {
			annots = append(annots, fieldRefs...)
		}
		w, h := p.Width, p.Height
		if w == 0 {
			w = 612
		}
		if h == 0 {
			h = 792
		}
		res := fmt.Sprintf("<< /Font << %s >>", fonts)
		if p.XObjects != "" {
			res += fmt.Sprintf(" /XObject << %s >>", p.XObjects)
		}
		res += " >>"
		body := fmt.Sprintf("<< /Type /Page /Parent %d 0 R /MediaBox [0 0 %g %g] /Resources %s /Contents %d 0 R", pages, w, h, res, content)
		if len(annots) > 0 {
			body += " /Annots [" + strings.Join(annots, " ") + "]"
		}
		body += " >>"
		b.Set(num, body)
		kids = append(kids, pageRef)
	}

	b.Set(pages, fmt.Sprintf("<< /Type /Pages /Kids [%s] /Count %d >>", strings.Join(kids, " "), len(kids)))
	cat := fmt.Sprintf("<< /Type /Catalog /Pages %d 0 R", pages)
	if len(fieldRefs) > 0 {
		cat += fmt.Sprintf(" /AcroForm << /Fields [%s] /DA (/Helv 0 Tf 0 g) /DR << /Font << /Helv %d 0 R >> >> >>", strings.Join(fieldRefs, " "), helv)
	}
	if d.Catalog != "" {
		cat += " " + d.Catalog
	}
	cat += " >>"
	b.Set(catalog, cat)
	return b.Bytes(catalog, d.Trailer)
}

// Simple builds a one-page document whose content stream draws text with
// the Helvetica resource /F1.
func Simple(text string) []byte {
	return Build(Document{Pages: []Page{{Content: ShowText(text, 12, 72, 720)}}})
}

// ShowText returns a content stream that draws s with /F1 at the given size
// and position.
func ShowText(s string, size, x, y float64) string {
	return fmt.Sprintf("BT /F1 %g Tf %g %g Td %s Tj ET\n", size, x, y, Literal(s))
}

// Paragraphs returns a content stream with one Tj per line, laid out from
// the top of the page down, so that a page holds many lines.
func Paragraphs(lines []string, size float64) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "BT /F1 %g Tf %g TL 36 770 Td\n", size, size*1.15)
	for _, l := range lines {
		sb.WriteString(Literal(l))
		sb.WriteString(" Tj T*\n")
	}
	sb.WriteString("ET\n")
	return sb.String()
}

// Standard security handler (PDF 1.7 reference, algorithms 3.2 to 3.5, R2).

var passwordPad = []byte{
	0x28, 0xBF, 0x4E, 0x5E, 0x4E, 0x75, 0x8A, 0x41, 0x64, 0x00, 0x4E, 0x56, 0xFF, 0xFA, 0x01, 0x08,
	0x2E, 0x2E, 0x00, 0xB6, 0xD0, 0x68, 0x3E, 0x80, 0x2F, 0x0C, 0xA9, 0xFE, 0x64, 0x53, 0x69, 0x7A,
}

type encState struct {
	key []byte
	o   []byte
	u   []byte
}

func padPassword(p string) []byte {
	b := append([]byte(p), passwordPad...)
	return b[:32]
}

func rc4Crypt(key, data []byte) []byte {
	c, err := rc4.NewCipher(key)
	if err != nil {
		panic(err)
	}
	out := make([]byte, len(data))
	c.XORKeyStream(out, data)
	return out
}

func newEncState(e *Encryption, fileID []byte) *encState {
	owner := e.OwnerPassword
	if owner == "" {
		owner = e.UserPassword
	}
	// Algorithm 3.3: the /O value.
	okey := md5.Sum(padPassword(owner))
	o := rc4Crypt(okey[:5], padPassword(e.UserPassword))

	// Algorithm 3.2: the file key. /P is -1.
	h := md5.New()
	h.Write(padPassword(e.UserPassword))
	h.Write(o)
	var p [4]byte
	binary.LittleEndian.PutUint32(p[:], 0xFFFFFFFF)
	h.Write(p[:])
	h.Write(fileID)
	key := h.Sum(nil)[:5]

	// Algorithm 3.4: the /U value for R2.
	u := rc4Crypt(key, passwordPad)
	return &encState{key: key, o: o, u: u}
}

func (e *encState) crypt(num int, data []byte) []byte {
	h := md5.New()
	h.Write(e.key)
	h.Write([]byte{byte(num), byte(num >> 8), byte(num >> 16), 0, 0})
	objKey := h.Sum(nil)[:10] // min(5+5, 16)
	return rc4Crypt(objKey, data)
}
