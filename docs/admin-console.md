# Admin console

The optional console runs on your own Cloudflare Worker; this repository does not provide a public hosted console. Cloudflare Access admits only the account owner configured by `MESHSCALE_OWNER_EMAIL`. The Worker verifies each Access JWT again before serving HTML, assets, or API responses.

## Features and data flow

The Machines view joins WARP registrations, physical devices, Mesh connectors and connector registrations. It shows Mesh IPs, owner, OS, online state and last seen time. Gateway list descriptions provide secure and exit-node capabilities. Cloudflare SSH targets identify Cloudflare SSH mode; device-local SSH mode cannot be read remotely and appears as `unknown`. The detail dialog previews node rename or device DNS alias and registration or node revoke. DNS names use the CLI's `meshscale dns:` ownership marker; Access rules use `meshscale rule:` and the same JSON policy shape as `meshscale rules`. Rules, DNS names and exit nodes have dedicated views. Every write requires a server-generated diff, a fingerprint that is recomputed against fresh account data, and an explicit confirmation checkbox. Only meshscale-owned Gateway rules may be changed. A later CLI sync can overwrite console policy and physical-device DNS aliases, so keep the CLI's local rules file and OS hostname synchronized.

The UI is static HTML/CSS plus a small TypeScript client. The client and server share an Effect `HttpApi` contract. The Worker caches a schema-decoded account snapshot in KV for 15 seconds and deletes that key after every write, including partial failures. KV records are schema-decoded on read and schema-encoded on write.

## Effect and Alchemy

`src/worker.ts` assembles the request handler. `Settings` reads account configuration through Effect `Config`, with the API token as `Config.Redacted`. `Cloudflare` owns external API calls and converts transport, timeout and schema failures to typed `CloudflareError`. `Storage` owns KV with typed `StorageError`. `Inventory` joins and validates Cloudflare records; `Console` plans and applies changes. `Access` verifies the Cloudflare assertion with the team's remote JWKS, issuer, audience, expiry, a 12-hour maximum token age, five seconds of clock tolerance, and exact owner email. `src/http.ts` combines typed `HttpApi` endpoints with HTML routes and applies the Access guard. Errors use `Schema.TaggedError`; tests replace live services with Layers. Effect 4.0.6 places HTTP modules in `effect/http` and `effect/http-api` and uses `Context.Service` with Layers, instead of the older `@effect/platform` API layout.

`control/alchemy.run.ts` owns the `meshscale-console` Worker, its assets, KV namespace, Worker bindings, secret, workers.dev hostname, and the owner-only Access application and policy. The dev stack is separate from other stages. Deploy and destroy use Alchemy only; do not manage these resources with Wrangler or the dashboard. The Worker uses the current Workers compatibility date, `nodejs_compat`, and sampled observability.

## Security and tokens

Cloudflare Access is the public gate. The Worker rejects absent, forged, expired, future-issued, stale, wrong-audience and non-owner JWTs. Non-GET requests also require a same-origin browser request and limit the actual streamed body to 256 KiB, regardless of Content-Length. Successful responses, authentication/CSRF denials, and body-limit errors use a restrictive CSP, no-store caching, and security headers. The Cloudflare API token is a Worker secret, never a browser value or Git file. Only the configured account ID is used for API paths. Access and the Worker each enforce owner identity; the API token alone cannot open the console.

Use a dedicated account-scoped token for `MESHSCALE_CONSOLE_API_TOKEN`. The required Cloudflare account permission groups are **Zero Trust Read** for registrations, physical devices, Gateway rules/lists and SSH targets; **Cloudflare One Connector: WARP Read/Edit** for Mesh node listing, rename and delete; and **Zero Trust Edit** for registration revoke and Gateway rule create/update/delete. Cloudflare currently exposes the Gateway and registration writes through the account-level Zero Trust permission, so the console's ownership checks are an additional boundary, not a token-level restriction. The deploy token (`CLOUDFLARE_API_TOKEN`) is separate and needs Workers script/assets/KV management plus Access Apps and Policies Edit. Check the [current permission catalogue](https://developers.cloudflare.com/fundamentals/api/reference/permissions/) when creating either token. The console token does not need Workers or Access administration permissions.

## Deploy and destroy

From `control/`, use Bun and `npm ci`. Put `CLOUDFLARE_ACCOUNT_ID`, `CLOUDFLARE_API_TOKEN`, `MESHSCALE_CONSOLE_API_TOKEN`, `MESHSCALE_OWNER_EMAIL`, `MESHSCALE_OWNER_IDP_ID`, and `MESHSCALE_TEAM_DOMAIN` in the ignored `.env`; never commit it. Run `npm run check`, then `npm run deploy`. `npm run plan` previews Alchemy changes. `npm run destroy` removes the dev stack and its Access app. Set `MESHSCALE_OWNER_IDP_ID` to an existing Access identity-provider UUID. The provisioned Access application restricts sign-in to that provider and the configured owner email. All resources are stage-owned. To compare live account inventory with the CLI without an Access browser session, run `bun scripts/verify-account.ts` and `meshscale status --json` on a configured host.

## Local verification and limits

Run `npm ci`, `npm run check`, and `npm run build` in `control/`. Tests replace
Cloudflare, KV, and Access key discovery with fakes; local checks require no
account credentials and make no Cloudflare account changes. The review also ran
`npm audit` with zero reported vulnerabilities. The browser client uses an
external script and stylesheet compatible with the response CSP; account data
inserted into HTML is escaped.

The API client rejects redirects, bounds headers and body reads separately to
15 seconds, and limits each response to 16 MiB. GET retries 429 and 5xx at most
three times with jitter and Retry-After; delays over one minute return the
error without retrying early; mutations are never automatically
replayed. Inconsistent page metadata and repeated cursors fail the inventory
load, preventing a partial inventory from authorizing a destructive plan.
Rule/DNS plans also fail when their required association, secure-directory or
SSH-target inventory is degraded. Apply recomputes its fingerprint from fresh
data before changing anything.

Access is the admission boundary. There is no application-level global request
quota or distributed mutation lock; an authenticated owner can consume API
quota, and concurrent applies are not a transaction. Use a single writer when
applying changes. A public multi-user service would need shared coordination
and abuse controls before expanding this owner-only design.

Historical Access redirects were observed in a private development deployment.
They establish an anonymous login gate, not successful owner sign-in or
sub-300 ms authenticated origin latency. No deployment or live account/API
verification was performed during the OSS hardening review.
