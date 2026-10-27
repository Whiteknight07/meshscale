`inspect-account.py` performs read-only discovery using the existing local
`~/.config/meshscale/dev.env`. It prints enrollment policies, never token values.
It is optional; deployment reads `.env` through Alchemy.

The Access application requires `MESHSCALE_OWNER_IDP_ID` at provision time. Set
it to the owner's existing Cloudflare Access identity-provider UUID; the app
restricts sign-in to that provider, redirects to it, and retains its owner-email
allow policy. No identity-provider discovery or deployment is needed for local
checks.

Run `npm run format` to format the console sources and configuration. `npm run
check` runs typechecking, formatting checks, ESLint, and the test suite. The
formatter uses explicit source/configuration paths and does not visit secret
files or Alchemy state.
