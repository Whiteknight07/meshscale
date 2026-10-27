# meshscale menu bar design

## Brief and first pass

A macOS utility for solo developers who already know Tailscale. Within two seconds, answer “am I connected?” and “which device can I reach?” Then copy an address or open SSH. The popover is 360 CSS px wide and never taller than 560 px. This is a frontend prototype; it changes no network configuration.

I read README.md, docs/plan.md, docs/design/frontend-design-skill.md, and cmd/meshscale/{status,ip,up,down,login,whoami,dns}.go, plus the status JSON serializer/tests and WARP connection type. Product architecture documents still describe Swift; this requested Vite frontend is a separate integration direction.

Initial idea: a small blue network diagram above a device list, with a large connection toggle and an account disclosure. The useful part is a network mark whose link opens when disconnected. A persistent diagram, oversized toggle, and decorative device tiles would waste the popover's limited space.

### Tokens

Six core light / dark pairs; blue and green are semantic, not washes:

| Token | Light | Dark | Use |
| --- | --- | --- | --- |
| Surface | #F7F7F8 | #292A2D | Opaque native-feeling popover |
| Inset | #EBECEF | #35363A | Pressed controls, command field |
| Ink | #202124 | #F3F3F5 | Primary text and template marks |
| Secondary | #62646C | #B0B2BA | Supporting copy, inactive icons |
| Action | #0067CF | #75B6FF | Primary actions, focus ring |
| Online | #247044 | #82C69B | Connection and online states |

Derived separator: ink at 12%; error: #B33629 / #FF9D91. No gradients. One restrained window shadow is allowed around the entire popover in the review harness; no row shadows. Corners: 12px window, 6px controls, 4px focused rows. Spacing: 4, 8, 12, 16, 20, 24px.

Type: `-apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif`. The installed macOS system font and its native rendering are intentional: this is a menu bar utility, not a branded website. Body 13/18, supporting 12/16, section labels 12/16 medium, device names 13/18 medium, connection state 16/20 semibold, onboarding heading 20/25 semibold. Only the executable command uses the system monospace stack. IPs use proportional system text with tabular numerals. No runtime font requests.

Layout: all content left aligned on a 16px inset; device icons sit on a shared rail, names and IPs share a second rail. Actions and online words align right. Use native list density and separators only between meaningful sections.

### Wireframes compared

A. Diagram-led (rejected: slow to scan, too much decorative chrome)

    +----------------------------------+
    | meshscale                     ⚙  |
    |           o---o---o              |
    |           Connected       [on]   |
    | [ laptop tile ] [ server tile ]  |
    | ...                              |
    +----------------------------------+

B. Status-led list (chosen)

    +----------------------------------+
    | [link] meshscale              ⚙  |
    | [link] Connected    [Disconnect] |
    |        via Cloudflare            |
    |----------------------------------|
    | This device                      |
    | [mac] macbook-air           [ > ] |
    |       100.96.0.2       [copy]     |
    |----------------------------------|
    | Other devices          3 online  |
    | [srv] homelab             Online |
    |       100.96.0.10           [ > ] |
    | [phn] pixel-9             Online |
    |       100.96.0.12           [ > ] |
    | [srv] nas                 Online |
    |       100.96.0.20           [ > ] |
    | [mac] old-thinkpad        Offline |
    |       Last seen 3 days ago  [ > ] |
    |----------------------------------|
    | alex@example.com               > |
    | Personal account           Quit  |
    +----------------------------------+

    Signed out / waiting / error       Device actions
    +----------------------------------+ +----------------------------------+
    | [link] meshscale                 | | [<] Devices                      |
    |                                  | | [srv] homelab            Online  |
    | Your devices, connected          | | Linux / last seen just now       |
    | Sign in to connect your devices  | |----------------------------------|
    | through your Cloudflare account. | | Copy Mesh IP       100.96.0.10   |
    | [Sign in with Cloudflare]        | | Copy name          homelab.mesh  |
    |                                  | | SSH in Terminal              >   |
    |                             Quit | |                                  |
    +----------------------------------+ | [account footer]                 |
                                         +----------------------------------+

Empty network keeps this device visible, then says “Add another device” with `meshscale up` and a Copy command action. It explicitly says to run it on another Linux device with meshscale installed and signed in. Signing in keeps “Sign in with Cloudflare” visible as the action name, provides browser direction and “Open browser again.” Disconnected preserves the device inventory, labels its freshness, and disables SSH until connected. Error offers “Connect” with a concrete repair instruction. Detail disables SSH for phones, offline devices, this device, and unconfirmed capability.

### Principles

1. Spend personality in the linked-node mark. Three slightly rounded nodes joined on an elbow suggest a small personal network, and the break in the disconnected variant is visible at menu bar size. Everything around it stays quiet.
2. Connection state comes before inventory. Local connection and remote online state are separate concepts; never infer local connection from a remote registration's recent activity.
3. Lists are for finding devices, not presenting metrics. Names lead; one-click IP copy is always available; device detail exposes names and SSH without row-menu clutter.
4. Only explicit actions produce feedback. No ambient motion; a small progress indicator is enough while waiting, and reduced motion stops it.
5. Plain copy, sentence case, stable action names. No sales copy, all-caps labels, arrows appended to words, faux terminals, or implementation terms in ordinary flows.

## Self-review before implementation

Brief review: a big network diagram obscures the two-second job; removed it and promoted the connection label. The initial toggle made “off” ambiguous between sign-out and disconnect; revised to named Connect / Disconnect buttons. Account actions need to fit without crowding the main list: keep email/account/quit in the footer, with Sign out in its disclosure. Use a real back button in device detail rather than a floating overlay.

AI-default review: this is neither cream/serif/clay, acid-on-black, newspaper columns, nor a SaaS card kit. System type, cool neutral opaque material, semantic macOS blue, and compact utility rows follow the subject. Removed the initial colored row backgrounds and decorative topology diagram. Monospace belongs only on the command, never tiny labels. No eyebrow labels, middle-dot meta strings, gradients, repeated cards, or animated entrances. Native utility familiarity is a deliberate requirement; distinctiveness belongs in the template mark rather than an unfamiliar layout.

## Build decisions

Vanilla TypeScript + Vite. A single small popover with a handful of states does not need a component runtime. Typed DOM rendering, delegated button events, safe text escaping, explicit focus restoration, and a single bridge subscription keep it small and framework agnostic. No remotely hosted assets. SVG icons are authored locally; template assets use black fills/strokes and transparent backgrounds.

All data and side effects pass through `src/bridge.ts`. `src/mock.ts` implements the interface for development and the standalone review file. The mock never launches a real browser, Terminal, or network command; these actions return an explicitly labeled preview receipt. Clipboard uses the browser clipboard only on a user click and reports failures. The mock sign-in waits for explicit completion in the dev review controls, avoiding screenshot races. Connect is asynchronous and cancellable. A supplied native bridge takes precedence; production without it shows a connection error instead of simulated success.

State URLs: `#signed-out`, `#signing-in`, `#connected`, `#disconnected`, `#connecting`, `#error`, `#empty`, `#device-detail`, `#offline-detail`, `#account`, `#settings`. Dev controls live outside the app window. Vite production excludes these controls unless `?review=1`; standalone preview enables them explicitly. Theme follows `prefers-color-scheme`; review-only overrides permit reproducible captures.

## Expected Go bridge contract (future Wails v3)

No Wails dependency or Go change is part of this work. The adapter should implement:

- `GetStatus() -> AppStatus`, `Connect()`, `Disconnect()`, `SignIn()`, `CancelSignIn()`, `SignOut()`.
- `Copy(text)`, `OpenSSH(deviceID)`, `Quit()`, `SetLaunchAtLogin(enabled)`; return rejected promises on failure, resolved void on success.
- `OnChange(callback) -> unsubscribe`, via one Wails status-change event carrying a complete `AppStatus` snapshot. The adapter should subscribe before `GetStatus`, guard stale initial reads, and release the subscription when the window closes.

The frontend `MeshBridge` methods use camelCase and promises. It accepts an injected `window.meshscaleBridge`; adapt generated Wails bindings into that interface in one place. `OpenSSH` must look up the device by ID on the Go side, validate capability/state again, then open Terminal with a safely constructed command. Never interpolate a frontend-supplied name into a shell. Clipboard, browser OAuth, launch-at-login and quit belong to Go. Errors use `{code, message, recovery}`; expose actionable sanitized text, never credentials.

`meshscale status --json` emits a **bare array**, not an object with local status. Its exact serializer fields are represented by `MeshDevice` (snake_case retained). Example fixture matching that output:

```json
[
  {"id":"reg-mac","device_id":"dev-mac","kind":"device","name":"macbook-air","dns_name":"macbook-air.mesh","user":"alex@example.com","ipv4":"100.96.0.2","os":"mac","online":true,"last_seen_at":"2026-10-26T12:00:00Z","this_machine":true},
  {"id":"node-homelab","registration_id":"reg-homelab","kind":"node","name":"homelab","dns_name":"homelab.mesh","user":"Mesh node","ipv4":"100.96.0.10","os":"linux","online":true,"last_seen_at":"2026-10-26T12:00:00Z","this_machine":false,"connection_state":"healthy"}
]
```

This is a source-verified example of the JSON output, not a live account query: `runStatus` persists mesh association state, so running it would write outside the authorized `app/` directory. No live account or host network command was run. `ipv6`, `registration_id`, `device_id`, `dns_name`, `user`, `os`, `last_seen_at`, and `connection_state` may be absent. IPv4 may be absent too. Zero devices serializes as `[]`. Do not fabricate DNS names or addresses when absent. DNS collision rules belong to `assignDNSNames`, not the UI.

`AppStatus` wraps that unchanged array with separate account, local connection, capability, preference, freshness and auth information:

```ts
{
  auth: 'signed-out' | 'signing-in' | 'signed-in';
  account?: { id: string; name: string; email?: string };
  connection: { state: 'connected' | 'connecting' | 'disconnected' | 'error'; reason?: string };
  devices: MeshDevice[];
  sshDeviceIds: string[]; // explicit confirmed capability, not guessed from OS
  updatedAt: string; // ISO date
  error?: { code: string; message: string; recovery: string };
  preferences: { launchAtLogin: boolean };
}
```

Important integration limits: `status --json` currently does **not** supply local WARP status, account identity, SSH availability, or launch-at-login state. Recent registration activity is a five-minute heuristic, not a reachability probe. The native service must combine `warpcli.Status`, account/session information (`whoami` is currently plain text), and confirmed SSH support. `up` / `down` currently guard for Linux; macOS enrollment/connection needs implementation. Keyless SSH is a product intent, not a claim that every Linux device accepts it. Names follow configured DNS suffix, default `.mesh`; DNS propagation can take about 60 seconds. Multiple Cloudflare accounts require a selection flow in the native integration; this prototype uses one personal account.

## Verification and visual critique

Completed with Chromium/Playwright at device scale factor 2. All 11 states have light and dark PNGs (22 total) under `frontend/screenshots/`. Every popover measures 360px wide; authentication is 344px tall, connected/disconnected/connecting 547px, error 558px, empty 462px, details 423px, account/settings 390px. All fit the requested 560px cap without horizontal overflow. The screenshot index links each capture; `verification.json` records the measurements and checks.

I inspected all first-pass captures and re-shot after these changes:

- The disconnected/connecting screen's extra instruction ran into the footer at the height cap. Removed the redundant instruction: the connection label, Connect action, and “Last known status” already communicate the same information. Connected rows retain their 56px scan rhythm.
- Error recovery initially pushed the offline device out of the first view. Tightened error-state rows to 44px and reduced recovery spacing so the explanation and the entire five-device inventory fit together at 558px. The inventory itself can scroll for larger real networks while connection and account chrome remain fixed.
- Signed-out copy now explicitly mentions browser sign-in in its single explanatory sentence.
- Full device-detail copy rows are clickable, rather than only the value. IP/name data remain selectable and copy success names the actual value.
- Keyboard activation exposed a focus-selector bug: a combined selector chose Settings before the device heading. Explicit priority now focuses the new heading and Escape restores the selected device. Stable focus keys survive status/feedback rerenders. Cancel stays actionable while Connect is pending, and an old completion cannot undo cancellation in the mock.

The final review retains quiet neutral surfaces, system type, ordinary semantic blue/green, native list density, and one recognizable linked-node motif. No card grid, ornamental diagram, gradient, decorative monospace label, all-caps eyebrow, or entrance animation was added. The disconnected mark works without color, and online states always have text as well as dots.

`npm run build` passes TypeScript and Vite; the app has zero runtime package dependencies. Final JS is approximately 19.8kB (7.1kB gzip), CSS 12.8kB (3.3kB gzip); standalone HTML is about 33kB. `npm run screenshots` passes with no browser errors. The checks cover clipboard IP/name/command values, copy feedback, SSH capability/offline/disconnected restrictions, connect/disconnect/cancel and late completion, browser waiting/retry/cancel/completion, sign-out, launch-at-login, focus and keyboard shortcuts, reduced motion, 320px width, native bridge injection, native clipboard/preference rejection with preference rollback, and a `file://` standalone load with all HTTP requests blocked. The screenshot harness explicitly reloads between scenarios; merely revisiting the same hash does not reset an already-open detail screen.

Limit: these are Linux Chromium screenshots. Native macOS WebKit/San Francisco rendering, menu bar anchoring, and template-image tinting must be checked in the eventual host. No real account query, OAuth, SSH, WARP change, network configuration, Go edit, commit, or push was performed.

## Open integration questions

1. The existing docs choose SwiftUI; this brief chooses a Wails-ready web frontend. Confirm the final macOS host and who owns popover anchoring, outside-click dismissal, and Escape-to-close at the root screen.
2. How will the macOS native service implement enrollment and connection, given that `up` and `down` currently enforce Linux? The frontend cannot infer success from registration recency.
3. Which devices actually expose keyless SSH, and which destination/user should Terminal use? Supply confirmed IDs/capability from Go; the UI does not guess from Linux alone.
4. When OAuth exposes several accounts, add a selection step using real account results. Cloudflare/Zero Trust setup prerequisites need separate actionable errors from Go.
5. Decide the refresh/event cadence and launch-at-login persistence on the native side. Preserve the distinction between stale inventory and live local connection state.
