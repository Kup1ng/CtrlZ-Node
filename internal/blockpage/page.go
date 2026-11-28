package blockpage

import (
	"bytes"
	"encoding/base64"
	"errors"
	"html/template"
	"strings"

	policyv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/policy/v1"
	"github.com/Kup1ng/CtrlZ-Shared/wire"
	"google.golang.org/protobuf/proto"

	"github.com/Kup1ng/CtrlZ-Node/internal/agent/sock"
)

// Page is a block page ready to be written: the stored BlockPage record with its
// logo already encoded as a data: URI, once, so that a connection writes it from
// this cache and holds no copy of its own (10.2).
type Page struct {
	// Custom is false for our own default page: no tenant text, no form.
	Custom  bool
	Title   string
	Message string
	Mode    policyv1.UnblockMode
	URL     string
	Profile []byte
	logoURI string // "data:image/png;base64,..." or empty
}

// defaultPage is what is served for no page, an empty hash, a page the agent does
// not hold and one that does not validate. It names nothing of any tenant.
var defaultPage = &Page{}

// cost is the page's weight in the 32 MiB LRU.
func (p *Page) cost() int64 {
	return int64(len(p.Title)+len(p.Message)+len(p.URL)+len(p.logoURI)) + 256
}

// ParsePage reads a stored BlockPage blob. The agent already hands over only a
// hash that quarantine validated, but this process is the one that renders it, so
// it validates again: a record that fails is not served as a tenant page.
func ParsePage(blob []byte) (*Page, error) {
	if len(blob) == 0 || len(blob) > sock.MaxPageBlob {
		return nil, errors.New("blockpage: page blob has the wrong size")
	}
	rec := &policyv1.BlockPage{}
	if err := proto.Unmarshal(blob, rec); err != nil {
		return nil, errors.New("blockpage: page blob does not parse")
	}
	if err := wire.ValidateBlockPage(rec); err != nil {
		return nil, errors.New("blockpage: page record is not valid")
	}
	p := &Page{Custom: true, Title: rec.Title, Message: rec.Message, Mode: rec.UnblockMode, URL: rec.UnblockUrl,
		Profile: append([]byte(nil), rec.ProfileId...)}
	if len(rec.Logo) > 0 {
		p.logoURI = "data:image/png;base64," + base64.StdEncoding.EncodeToString(rec.Logo)
	}
	return p, nil
}

// logoSentinel stands in the template for the logo's data: URI, which is then
// written from the cache between the two rendered halves. Rendering a 340 KiB
// string through the template per connection would copy it into a buffer each time.
const logoSentinel = "ctrlzlogosentinel0123456789"

// logoTagOpen and logoTag are the template's own text around the sentinel.
const (
	logoTagOpen = `<img class="logo" alt="" src="`
	logoTag     = logoTagOpen + logoSentinel + `">`
)

type texts struct {
	Lang, Dir                                          string
	DefTitle, DefMessage, Blocked, Button, Label, Link string
	Received                                           string
}

var textFA = texts{Lang: "fa", Dir: "rtl",
	DefTitle:   "این نشانی مسدود شده است",
	DefMessage: "دسترسی به این نشانی از طریق تنظیمات DNS شما مسدود شده است.",
	Blocked:    "نشانی مسدودشده",
	Button:     "درخواست رفع انسداد",
	Label:      "پیام شما (اختیاری)",
	Link:       "درخواست رفع انسداد",
	Received:   "درخواست شما ثبت شد.",
}

var textEN = texts{Lang: "en", Dir: "ltr",
	DefTitle:   "This address is blocked",
	DefMessage: "Access to this address is blocked by your DNS settings.",
	Blocked:    "Blocked address",
	Button:     "Request unblock",
	Label:      "Your message (optional)",
	Link:       "Request unblock",
	Received:   "Your request was received.",
}

// pickLang chooses the page's language from Accept-Language: Persian by default,
// English when it is listed and Persian is not listed before it (10.4).
func pickLang(accept string) *texts {
	for _, part := range strings.Split(accept, ",") {
		tag := strings.ToLower(strings.TrimSpace(part))
		if i := strings.IndexByte(tag, ';'); i >= 0 {
			tag = strings.TrimSpace(tag[:i])
		}
		switch {
		case tag == "fa" || strings.HasPrefix(tag, "fa-"):
			return &textFA
		case tag == "en" || strings.HasPrefix(tag, "en-"):
			return &textEN
		}
	}
	return &textFA
}

type view struct {
	T        *texts
	Title    string
	Message  string
	Name     string
	Nonce    string
	Brand    bool
	Logo     bool
	LogoURL  template.URL
	Form     bool
	Token    string
	Link     string
	Received bool
}

// The page has no script and no external file. The style is inline under a nonce;
// colours follow the system's light or dark setting; fonts are the system's.
var pageTmpl = template.Must(template.New("page").Parse(`<!doctype html>
<html lang="{{.T.Lang}}" dir="{{.T.Dir}}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex">
<title>{{.Title}}</title>
<style nonce="{{.Nonce}}">
:root{color-scheme:light dark;--bg:#f5f6fa;--card:#fff;--ink:#161a23;--mute:#5b6372;--line:#dde1ea;--accent:#3355ff;--on:#fff}
@media (prefers-color-scheme:dark){:root{--bg:#0d1017;--card:#161b25;--ink:#e9ecf3;--mute:#9aa3b5;--line:#272e3d;--accent:#7b93ff;--on:#0d1017}}
*{box-sizing:border-box}
body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:16px;background:var(--bg);color:var(--ink);font:16px/1.6 system-ui,-apple-system,"Segoe UI",Tahoma,Roboto,sans-serif}
main{width:100%;max-width:480px;background:var(--card);border:1px solid var(--line);border-radius:16px;padding:28px 24px}
.logo{display:block;max-width:160px;max-height:96px;margin:0 auto 16px}
h1{font-size:1.35rem;line-height:1.35;margin:0 0 12px;text-align:center}
p{margin:0 0 16px;white-space:pre-wrap;overflow-wrap:anywhere}
.name{margin:0 0 16px;text-align:center;color:var(--mute);font-size:.9rem}
.name code{display:block;direction:ltr;unicode-bidi:isolate;color:var(--ink);font-size:1rem;overflow-wrap:anywhere}
form{margin-top:20px}
label{display:block;margin-bottom:6px;color:var(--mute);font-size:.9rem}
textarea{width:100%;min-height:96px;resize:vertical;padding:10px;border:1px solid var(--line);border-radius:10px;background:transparent;color:inherit;font:inherit}
button,.btn{display:inline-block;margin-top:12px;padding:10px 18px;border:0;border-radius:10px;background:var(--accent);color:var(--on);font:inherit;font-weight:600;text-decoration:none;cursor:pointer}
.act{text-align:center}
.brand{margin:20px 0 0;text-align:center;color:var(--mute);font-size:.8rem}
</style>
</head>
<body>
<main>
{{if .Logo}}<img class="logo" alt="" src="{{.LogoURL}}">{{end}}
<h1>{{.Title}}</h1>
{{if .Received}}<p>{{.T.Received}}</p>{{else}}
{{if .Message}}<p>{{.Message}}</p>{{end}}
<div class="name">{{.T.Blocked}}<code>{{.Name}}</code></div>
{{if .Form}}<form method="post" action="/.ctrlz/unblock">
<input type="hidden" name="t" value="{{.Token}}">
<label for="m">{{.T.Label}}</label>
<textarea id="m" name="m" maxlength="500"></textarea>
<button type="submit">{{.T.Button}}</button>
</form>{{end}}
{{if .Link}}<div class="act"><a class="btn" href="{{.Link}}" rel="noopener noreferrer">{{.T.Link}}</a></div>{{end}}
{{end}}
{{if .Brand}}<div class="brand">Ctrl Z</div>{{end}}
</main>
</body>
</html>
`))

// rendered is a page split around the logo's place: head, then the logo URI from
// the cache, then tail. A page with no logo has everything in head.
type rendered struct {
	head, tail []byte
	logo       string
}

func (r *rendered) size() int { return len(r.head) + len(r.logo) + len(r.tail) }

// render builds the document for one connection. token is empty when the page
// has no form. The tenant's text is escaped by html/template; the nonce is fresh
// for every response.
func (p *Page) render(lang *texts, name, nonce, token string) (*rendered, error) {
	v := view{T: lang, Name: name, Nonce: nonce}
	if !p.Custom {
		v.Title, v.Message, v.Brand = lang.DefTitle, lang.DefMessage, true
	} else {
		v.Title, v.Message = p.Title, p.Message
		if v.Title == "" {
			v.Title = lang.DefTitle
		}
		if v.Message == "" {
			v.Message = lang.DefMessage
		}
		// No brand when the user set a logo (10.4).
		v.Brand = p.logoURI == ""
		v.Logo = p.logoURI != ""
		v.LogoURL = template.URL(logoSentinel)
		switch p.Mode {
		case policyv1.UnblockMode_UNBLOCK_MODE_REQUEST:
			v.Form, v.Token = token != "", token
		case policyv1.UnblockMode_UNBLOCK_MODE_URL:
			v.Link = p.URL
		}
	}
	return finish(&v, p.logoURI)
}

// renderReceived is the answer to an accepted or rate-limited unblock form: the
// same page with a line of thanks and no form, so an over-limit sender learns
// nothing from the difference (10.4).
func (p *Page) renderReceived(lang *texts, name, nonce string) (*rendered, error) {
	v := view{T: lang, Name: name, Nonce: nonce, Received: true, Title: lang.DefTitle, Brand: true}
	if p.Custom && p.Title != "" {
		v.Title = p.Title
	}
	if p.Custom {
		v.Brand = p.logoURI == ""
		v.Logo = p.logoURI != ""
		v.LogoURL = template.URL(logoSentinel)
	}
	return finish(&v, p.logoURI)
}

func finish(v *view, logoURI string) (*rendered, error) {
	var buf bytes.Buffer
	if err := pageTmpl.Execute(&buf, v); err != nil {
		return nil, errors.New("blockpage: the page did not render")
	}
	out := &rendered{}
	if !v.Logo {
		out.head = buf.Bytes()
		return out, nil
	}
	// The place is found by the whole tag around the sentinel, not by the sentinel's
	// own text: a title or message a tenant wrote can hold those letters, but
	// html/template escapes the "<" of any text, so the tag cannot come from data.
	i := bytes.Index(buf.Bytes(), []byte(logoTag))
	if i < 0 {
		return nil, errors.New("blockpage: the logo place is missing")
	}
	b := buf.Bytes()
	i += len(logoTagOpen)
	out.head, out.tail, out.logo = b[:i], b[i+len(logoSentinel):], logoURI
	return out, nil
}
