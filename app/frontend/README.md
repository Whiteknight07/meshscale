# meshscale menu bar frontend

A 360px macOS menu bar popover built with vanilla TypeScript and Vite. System light/dark appearance, local SVG icons, no external fonts or runtime dependencies. Design decisions and the native integration contract are in [../DESIGN.md](../DESIGN.md).

## Review

Open [preview.html](preview.html) directly in a browser. It is self-contained, includes all mock states and appearance controls, and makes no network requests. Clipboard needs a browser that permits clipboard access on local files; a denial produces a visible error. SSH, browser sign-in and Quit are simulated and labeled as previews. Complete sign-in using the development control below the popover.

Or run the dev server:

```sh
cd app/frontend
npm ci
npm run dev
```

Open `http://127.0.0.1:5173/#connected`. The selector below the window changes the hash. Available states:

`signed-out`, `signing-in`, `connected`, `disconnected`, `connecting`, `error`, `empty`, `device-detail`, `offline-detail`, `account`, `settings`.

Appearance defaults to the OS. Light/dark overrides are confined to review controls. Tab and Shift-Tab traverse actions, up/down move between controls, Enter activates, and Escape returns from a detail screen or dismisses feedback. Settings includes a native checkbox for launch at login.

## Build and screenshots

```sh
cd app/frontend
npm run build
```

This typechecks, creates `dist/`, and regenerates the inlined `preview.html`. The production bundle only enables mock/review controls when `?review=1` is explicitly supplied. A normal native build uses `window.meshscaleBridge` and displays a service error if it is missing. The standalone preview opts into review mode itself.

With the dev server running, capture and verify all states:

```sh
cd app/frontend
npx playwright install chromium
npm run screenshots
```

Use `MESHSCALE_REVIEW_URL` to point the script at another local dev port. Screenshots are Chromium captures at device scale factor 2. On macOS the system font will resolve to San Francisco; these Linux captures use the installed sans-serif fallback, so macOS WebKit text rendering still needs a final integration check.

Screenshots and verification JSON are generated locally; see the
[capture notes](screenshots/README.md) for artifacts omitted from public source.

## Native bridge

`src/bridge.ts` is the only data/action contract. Both initial snapshots and
status events are validated at runtime before rendering; malformed data produces
a service error instead of entering HTML attributes. Inject one `MeshBridge` on `window.meshscaleBridge` before the frontend module starts. The mock in `src/mock.ts` implements the same contract. UI modules never call Go, the network, the clipboard, or Terminal directly.

- Status: `getStatus(): Promise<AppStatus>` and `onChange(callback): unsubscribe`.
- Network/session actions: `connect`, `disconnect`, `signIn`, `cancelSignIn`, `signOut`.
- Native utilities: `copy(text)`, `openSSH(device)`, `quit`, `setLaunchAtLogin(enabled)`.

The Go adapter should send only a validated device ID for SSH, handle browser OAuth and clipboard natively, and publish complete status snapshots after changes. Device JSON preserves the CLI's snake_case fields. The wrapper supplies account identity, local connection state, explicit SSH capability, timestamp, preferences and actionable errors. No real credentials belong in frontend state. See [DESIGN.md](../DESIGN.md) for JSON examples, method mapping, and current CLI limitations.

[Template icons](public/icons/README.md) are provided at 16pt and 18pt with connected/disconnected variants.

Run `npm test` (Node 22.18+ or Node 24+) for native-message validation regressions.
`npm ci` installs the committed lockfile; `npm run build` typechecks and produces
the local assets and standalone preview without external runtime assets. The OSS
review's `npm audit` reported zero vulnerabilities. DOM display text and
attribute values from account/device data are escaped.
