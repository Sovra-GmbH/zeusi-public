# zeusi.ai landing page

Static HTML + CSS for the zeusi.ai landing page, plus two small same-origin scripts (`connect.js`, `wow.js`) that only enhance it. No build step, no tracking, no third-party requests (the one exception: after "Watch with sound" is pressed, the full film is fetched from its public Vercel Blob URL; see "The hero film").

**Live at <https://zeusi.ai>.** The site is deployed to Vercel as static files straight from `site/` (no build step). This `README.md` is not uploaded.

## Deploy order: the MCP server first, then the site

**Deploy the MCP server (with workspace writes on) before the site, never the site first.** The site quotes the server word for word, so a site that goes live ahead of its server promises text the server does not send yet:

1. Deploy the MCP server release this site matches, with workspace writes on (filling enabled). The startup strip (`#first-run-demo`) shows the "filling on" reply (form B: "Want me to fill your memory now? I'll show a preview first."). With writes off the server sends the read-only reply (form A), and the strip would not match. The welcome's "another user's Zeusi sign-in cannot read it" also ships with that server release; until then the live server still sends the older wording.
2. Smoke-check on a brand-new account: `zeusi_startup` returns the same `message` and `welcome` as the strip (`test/site-terminal.test.ts` runs the same check against the real handler in CI).
3. Then deploy the site.

## Open it locally

```sh
npx serve site            # or: python3 -m http.server 8080 --directory site
```

Opening `site/index.html` directly in a browser also works.

## Files

- `index.html`: hero (logo, headline, three-line subhead, "Connect your AI" button, the film slot), the `#first-run-demo` startup terminal, the `#connect` section, the `#first-5-minutes` guide, the `#remembers` example cards and the `#about` section.
  - **Connect your AI**: one line on MCP (the open standard for AI connectors), the server URL `https://mcp.zeusi.dev/mcp` in a large field with a Copy button, and an app picker with exact steps for Claude (web & Desktop), Claude Code, ChatGPT, Cursor, VS Code, Gemini CLI and any MCP client. Steps and UI labels come from each vendor's official docs (listed in `docs/hosting.md`, "OAuth for MCP clients"). Then "What happens when you sign in" (any GitHub account, its own empty workspace; Zeusi shows which app asks and where access goes; you approve read access, plus writing into your own workspace only after a preview you approve) and three example prompts.
  - Client names are plain text; no vendor logos. No token (only the `$ZEUSI_READ_TOKEN` placeholder), database host or infrastructure id, and no local `dist/mcp.js` path.
  - The steps assume the "any client" OAuth release of the hosted server is deployed; deploy the site after it.
  - **Your first 5 minutes** (`#first-5-minutes`): five numbered steps: add the one URL as a connector (the app steps above), sign in with GitHub (no invite; your own empty workspace, which another user's Zeusi sign-in cannot read), "Run zeusi_startup" (you see "Hello, I'm Zeusi"), "What can Zeusi do?" (reads `zeusi://about`), and "Fill your memory" (preview first, nothing saved until you say yes; how a rule and a decision come about; never paste secrets or private client details). The wording follows the welcome in `src/about.ts`; `test/site.test.ts` pins both. Deploy the site after the server release that serves the welcome.
- **Footer** (every page): the operator line "Zeusi is run by Sovra GmbH, Cham, Switzerland." and links to `/privacy`, `/terms` and `/security`. Same markup on all four pages (the current page carries `aria-current="page"`).
- `privacy/index.html`, `terms/index.html`, `security/index.html`: the Privacy, Terms and Security pages, served at `https://zeusi.ai/privacy`, `/terms` and `/security`. Each is a directory index on purpose: Vercel serves `site/<page>/index.html` at `/<page>` from the static files with no `vercel.json` and no project setting (a flat `privacy.html` would answer only at `/privacy.html` without `cleanUrls`). They use `../styles.css` and `../favicon.svg`, no script. The draft status was removed on Privacy and Terms by owner decision (21 Nov 2026): the visible "Draft — under review" line and the "Draft" at the start of their meta descriptions are gone, and `test/site-pages.test.ts` fails if the word "draft" comes back in any page's title, meta description or visible text. The remaining unknowns (data processing agreements and transfers, retention periods, how long Fly.io keeps disk snapshots, removal of pre-delete snapshots, and the EU-representative question) are visible `[TODO: …]` / `[Open question: …]` spans. The legal wording uses the owner's defaults of 21 Nov 2026 and, on Privacy, the structure and wording of counsel's v0.1 privacy-policy template, cut down to what Zeusi does; it still needs legal review. Facts are sourced from the code, the live servers, sovra.ch and the owner's Neon read; `test/site-pages.test.ts` pins the footer, the routing, the no-name / wall / over-claim / no-pricing checks on every page and the facts the pages quote. On that topic they carry only the landing page's one allowed negative sentence (`test/helpers/overclaim.ts`), with the owner's TODO HTML comment beside it on Privacy and Security (the one exact exemption in that file; replace it only after the owner approves new wording).
- `connect.js`: progressive enhancement, loaded with `defer`. Shows the Copy buttons (Clipboard API, with a select-the-text fallback; "Copied" is announced through an `aria-live` region) and turns the stacked panels into WAI-ARIA tabs (roving tabindex; Left / Right / Home / End). No network, no `innerHTML`, no `eval`. Without it, every panel shows with its own heading and the URL and commands stay selectable.
- `wow.js`: progressive enhancement, loaded with `defer` (no request of its own, no `innerHTML`, no `eval`):
  - **Film** (`#film`): see "The hero film" below.
  - **Startup terminal** (`#first-run-demo`): the static `<pre class="term-full">` shows your request, a summary of three fields of the reply (`workspace`, `empty`, `rules_served`), and then the `message` and `welcome` of the server's `zeusi_startup` reply for a brand-new, empty personal workspace with filling on, copied word for word and line for line. The reply has more fields, which the strip does not show; the lead above the strip says so. It is the text screen readers read and it reserves the box size. On scroll-in, `wow.js` types the same lines into an `aria-hidden` overlay; under `prefers-reduced-motion` nothing is typed. `test/site-terminal.test.ts` boots the real hosted handler and fails if the site drifts from the live reply: when the server wording changes, regenerate the lines (one `<span class="tl">` per line, rendering rule in `test/helpers/site-terminal.ts`).
  - **Paw trail**: paw prints behind a mouse or pen on the two "Connect your AI" buttons only (`pointer: fine` and `hover: hover`, never under reduced motion). One fixed, `pointer-events: none` layer; at most 12 prints, each removed when its fade ends.
  - **What Zeusi remembers** (`#remembers`): three example cards (decision, lock, source), visibly labelled "Example — not real data". Values are the server's own documented examples (`src/about.ts` `DECISION_EXAMPLE_*`, `RULE_EXAMPLE_*`) and the field names are the wire names. They flip in on scroll; without JS or under reduced motion they are simply shown.
- `test/site.test.ts` pins the labels, the URL, the steps per app, the script rules and the secret-free posture.
- `styles.css`: all styles. System font stack, no web fonts.
- `logo.svg`: the zeusi wordmark (cat-ear mark on the i), redrawn from the light mockup. Strokes use `currentColor`; the file defaults to forest green `#4f5d42` for light surfaces. The page inlines the same paths and colours them cream `#fef7ed` on the dark hero.
- `favicon.svg`: the eared "i" from the wordmark on the hero navy. The hosted MCP server serves the same file at `https://mcp.zeusi.dev/favicon.svg`.
- `logo-512.png`: the same mark rasterized at 512×512 (RGBA, transparent rounded corners, cream `#fef7ed` on navy `#10141d`). Used as the connector / plugin listing icon. Live at `https://zeusi.ai/logo-512.png` and at `https://mcp.zeusi.dev/favicon.png`.
- `assets/film/`: the four film files (poster, muted loop as WebM and MP4, the full film with sound); see "The hero film" below.
- `assets/hero.{avif,webp,jpg}`: the dark-mockup illustration (cat around the glowing orb), 580×720, cropped so no mockup headline text remains. Served through `<picture>`, AVIF first.

## The hero film

The film is in `site/assets/film/` (four files). The poster and the muted loop are served as plain static files, same origin. The full film with sound is served from its public Vercel Blob object (same bytes as `site/assets/film/zeusi-explainer-full-1080p.mp4`, which stays in the repo as the canonical file). **The one config point** is the `data-*-src` attributes on the `#film` element in `index.html`:

```html
<div class="film" id="film"
     data-poster-src="assets/film/zeusi-poster.jpg"
     data-loop-webm-src="assets/film/zeusi-hero-loop-720p.webm"
     data-loop-mp4-src="assets/film/zeusi-hero-loop-720p.mp4"
     data-sound-src="https://mwukcp9aqefvqnk6.public.blob.vercel-storage.com/assets/film/zeusi-explainer-full-1080p.mp4"
     data-captions-src="" data-captions-lang="en" data-captions-label="English">
```

| Attribute | File | What it does |
|---|---|---|
| `data-poster-src` | `zeusi-poster.jpg` (1920×1080, also the loop's first frame) | The poster of both videos. The visible `<img class="film-poster">` just below uses the same path (with `width="1920" height="1080"`, lazy); `test/site.test.ts` checks the two agree. |
| `data-loop-webm-src` | `zeusi-hero-loop-720p.webm` (VP9, muted) | The muted looping preview, listed first. |
| `data-loop-mp4-src` | `zeusi-hero-loop-720p.mp4` (H.264, muted) | The preview's fallback for browsers without WebM. |
| `data-sound-src` | the Blob URL of `zeusi-explainer-full-1080p.mp4` (~37 MB, with sound) | The full film. **Loaded only when "Watch with sound" is pressed** (click, tap, Enter or Space), never on page load, on scroll or during the preview. Empty = no button, "Film coming soon". |
| `data-captions-src` (optional) | a `.vtt` | Captions for the full film; `data-captions-lang` / `data-captions-label` name it. Empty today. |

The poster, loop and captions paths must be same-origin relative paths under `assets/film/`. `data-sound-src` is pinned to exactly `https://mwukcp9aqefvqnk6.public.blob.vercel-storage.com/assets/film/zeusi-explainer-full-1080p.mp4`. `test/site.test.ts` pins all of them and refuses any other absolute, `//` or third-party URL.

**Why the full film comes from Blob, and the rewrite that must not ship.** A `<video>` loads with HTTP Range requests (Safari: `bytes=0-1`, then `bytes=0-39406820`, then `bytes=2-…`), and each must be answered with exactly the bytes asked for. An earlier deploy-only `vercel.json` rewrote the same-origin path `/assets/film/zeusi-explainer-full-1080p.mp4` to the Blob object. Vercel's CDN cached **one** byte-range slice of that rewrite (no `Vary: Range`) and served it for every later Range request (`206 Content-Range: bytes 0-1/39406821`). iOS Safari then rejected `play()` with `NotSupportedError` and the page showed "The film could not be loaded." (desktop Chrome broke the same way). The Blob URL answers every Range correctly, so the page points at it directly. **A same-origin rewrite or proxy to Blob must not ship** (no `vercel.json` rewrite, no edge proxy). It was not the encoding (the same file plays from the Blob URL in WebKit and Chromium), not a lost user gesture, and not `preload="none"`. Do not re-encode to "fix" it.

**After a deploy, check:** on an iPhone (or Playwright WebKit iPhone emulation) and in desktop Chromium, press "Watch with sound" and confirm the film plays with sound past the first seconds.

**Swapping a film file:** replace the file in `site/assets/film/` with a new one **under the same name** (drop-in; no HTML change, no re-encode step here). For the full film, also upload the new bytes to the Blob object (a new Blob URL means changing `data-sound-src`, `FILM_SOUND_URL` in `test/site.test.ts` and the URL in this README). Keep the poster 1920×1080 (or change the `<img>` `width`/`height` to its real size) so nothing shifts. A new name means changing the attribute (and, for the poster, the `<img>` `src`) and the file list in `test/site.test.ts`. The 37 MB file stays a normal git file (under GitHub's 100 MB limit; no Git LFS).

**Deploy the film after the server too:** see "Deploy order" above (the MCP server with workspace writes on first, then the site).

How it behaves (`wow.js`, section 1):

- **Before anything is played:** the poster loads (lazy; ~208 KB). No video file is requested: there is no `<video>` in the markup and no preload of a film file.
- **Muted preview:** a `<video muted loop playsinline preload="none">` with `<source>` WebM first, then MP4, made only when the slot is at least 35% on screen AND `prefers-reduced-motion` is not set AND the browser does not ask to save data. It pauses when the slot leaves the screen. It never carries the full film. While it runs, a "Pause preview" / "Play preview" button is always visible in the top-right corner (WCAG 2.2.2); a preview the user paused stays paused when the slot scrolls back in. If the preview cannot load, it is removed and the poster stays.
- **"Watch with sound":** does not unmute the preview (the preview is a short loop, not the explainer). It stops and removes the preview and makes a second `<video>` whose `src` is `data-sound-src` (the Blob URL), so the 37 MB file is requested for the first time then. It plays with sound and native controls, gets focus, and "Playing the film with sound." is announced. If the full film cannot load, "The film could not be loaded." is shown and announced.
- **Stacking:** every video is inserted below the overlay, and the overlay stacks above it (`z-index`), so "Watch with sound" stays visible, the hit target for mouse and touch, and its focus ring stays visible while the preview plays.
- **Reduced motion / Save-Data:** no preview at all; the poster and "Watch with sound" show; the full film still loads only on the button.
- **Without JavaScript:** the poster and "Turn on JavaScript to play the film." show; no media request.

## Content Security Policy

No deploy config is shipped for the site (and none may rewrite the film to Blob; see "The hero film"). The page works under:

```
default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; media-src 'self' https://mwukcp9aqefvqnk6.public.blob.vercel-storage.com; font-src 'none';
connect-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'
```

(no inline script, inline handler, `eval`, or `style=` attribute; `wow.js` sets only CSS custom properties through the CSSOM, which `style-src 'self'` allows).

## Regenerating the hero images

The committed images are already optimized. If the source crop changes:

```sh
SRC=path/to/hero-source.jpg
ffmpeg -i "$SRC" -frames:v 1 -c:v libsvtav1 -crf 32 -preset 4 -pix_fmt yuv420p10le -f avif site/assets/hero.avif
cwebp -q 80 -m 6 "$SRC" -o site/assets/hero.webp
ffmpeg -i "$SRC" -q:v 4 site/assets/hero.jpg
```
