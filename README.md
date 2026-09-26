# @pipeworx/technographics

What a website is built with, read from the page itself. Keyless.

Part of [Pipeworx](https://pipeworx.io) — an MCP gateway connecting AI agents to 1683+ live data sources.

## Tools

- `tech_detect(url)` — the stack a site loads: ecommerce platform, payments, CMS, JS framework, analytics, marketing automation, chat, ad pixels, CDN, web server, visitor-identification tools. Each detection carries the evidence that produced it.
- `tech_detect_coverage()` — every technology the detector recognises, by category, and what it cannot see.

## The route taken, and the licence reasoning

**We wrote our own signatures. We did not use a Wappalyzer ruleset.** That is the whole
licence story and it is the part a future maintainer will need:

| Project | Licence | What it actually is |
|---|---|---|
| `enthec/webappanalyzer` | **GPL-3.0** | the maintained continuation of Wappalyzer's fingerprints |
| `HTTPArchive/wappalyzer` | **GPL-3.0** | HTTP Archive's fork of the same |
| `projectdiscovery/wappalyzergo` | MIT | MIT **code** — its README states it uses data from the two above |
| `rverton/webanalyze` | MIT | same shape: MIT code, Wappalyzer-lineage data |

Wappalyzer relicensed off MIT before going commercial and every maintained fork inherited
the copyleft. An MIT wrapper does not change the licence of the database it consumes, so
"use the MIT one" is not the escape it looks like.

What `src/signatures.ts` contains instead is our own expression of publicly observable
facts — that Shopify sets a `_shopify_y` cookie, that Cloudflare answers with `cf-ray`,
that Next.js emits `__NEXT_DATA__`. Those facts are not anyone's property; a particular
curated database of them is. No GPL code or data is used, imported, or vendored.

**What that costs:** ~167 technologies across 29 categories, where a commercial set covers
tens of thousands. That trade is stated in every response rather than hidden.

## Two honest limits, carried on every response

- **JavaScript is not executed.** We read the HTML the server returned. Anything a tag
  manager injects client-side is invisible — and for this category that is a specific,
  large blind spot, not a rounding error, because tag managers are exactly how marketing
  tools get installed. A site showing only "Google Tag Manager" may be running a dozen
  tools underneath it.
- **Absence is not evidence of absence.** A technology missing from an answer may simply
  be outside the signature set. `tech_detect_coverage()` exists so a negative can be
  checked before it is trusted.

## Evidence, not booleans

Every detection returns the string that matched — `cookie _shopify_y`,
`response header x-vercel-id: …`, `resource https://js.stripe.com/v3`. A detector whose
answers cannot be checked is one people stop trusting the first time it is wrong, and
during development this caught a real bug: `vercel.com` reported **Mintlify** because the
page merely *names* Mintlify in a customer logo. Patterns now key on what a technology
emits, never on a product name in prose.

## Fetching a caller-supplied URL, safely

This tool fetches an address the caller chose, which is the one shape that turns a data
gateway into someone's proxy into private space. So: http/https only, standard ports only,
and private, loopback, link-local (including cloud metadata at `169.254.169.254`), CGNAT
and multicast addresses are refused. Redirects are followed manually with **every hop
re-checked** — a public URL that 302s to the metadata endpoint is the actual attack, and a
first-hop-only check does not stop it. Response bodies are capped at 1.5 MB.

## Source

The live website. No third-party API, no key, no vendor.

## Quick Start

Add to your MCP client (Claude Desktop, Cursor, Windsurf, etc.):

```json
{
  "mcpServers": {
    "technographics": {
      "url": "https://gateway.pipeworx.io/technographics/mcp"
    }
  }
}
```

### What this endpoint actually serves

`tools/list` at `https://gateway.pipeworx.io/technographics/mcp` returns the tools in the table
above **plus the shared Pipeworx meta-tools** — `ask_pipeworx`,
`discover_tools`, `search_within`, `remember`/`recall` and the rest of the
gateway-wide set. So the tool count you see is larger than this table: a
single-pack endpoint currently lists roughly 30 shared tools alongside the
pack's own. The connection's `initialize` response states its exact scope, and
is the authoritative answer for a given day.

This is deliberate, not multiplexing by accident. The meta-tools are what let a
scoped connection answer a question this pack does not cover — via
`ask_pipeworx`, which routes across the whole catalog — without you adding a
second MCP server. There is currently no way to mount a pack endpoint without
them; if the extra schemas cost you more context than the routing is worth,
connect to the full gateway once rather than to several pack endpoints.

Or connect to the full Pipeworx gateway to get every pack's tools listed
directly, instead of just this one's:

```json
{
  "mcpServers": {
    "pipeworx": {
      "url": "https://gateway.pipeworx.io/mcp"
    }
  }
}
```

Both URLs reach the same gateway and the same 1683+ data sources. The
only difference is which pack's tools are listed **directly**; `ask_pipeworx`
reaches all of them from either one.

## No MCP client? Call it over HTTP

```bash
curl -X POST https://gateway.pipeworx.io/v1/tools/tech_detect \
  -H 'Content-Type: application/json' \
  -d '{"url":"shopify.com"}'
```

No account needed for the first calls. Inspect any tool: `GET https://gateway.pipeworx.io/v1/tools/tech_detect`. Find one: `POST https://gateway.pipeworx.io/v1/tools/search_packs` with `{"query":"..."}`.

## Standalone (no gateway account)

This package also runs as a local stdio MCP server — no Pipeworx account, no
gateway round-trip:

```json
{
  "mcpServers": {
    "technographics": {
      "command": "npx",
      "args": ["-y", "@pipeworx/mcp-technographics"]
    }
  }
}
```

Or run it directly to confirm it starts:

```bash
npx -y @pipeworx/mcp-technographics
```

It speaks MCP over stdin/stdout and answers `initialize`/`tools/list`/`tools/call`
for **only** this pack's tools — none of the shared meta-tools the gateway
connection above adds. Same source, same tools, no ask_pipeworx routing.

## Using with ask_pipeworx

Instead of calling tools directly, you can ask questions in plain English —
this works on the pack endpoint above as well as on the full gateway:

```
ask_pipeworx({ question: "your question about Technographics data" })
```

The gateway picks the right tool and fills the arguments automatically.

## More

- [Docs and guides](https://pipeworx.io/docs)
- [pipeworx.io](https://pipeworx.io)

## License

MIT
