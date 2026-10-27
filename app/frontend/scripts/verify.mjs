import { chromium, expect } from '@playwright/test'
import { mkdir, writeFile } from 'node:fs/promises'
import { fileURLToPath } from 'node:url'

const base = process.env.MESHSCALE_REVIEW_URL || 'http://127.0.0.1:5173/'
const root = new URL('../', import.meta.url)
const shots = new URL('screenshots/', root)
await mkdir(shots, { recursive: true })
const states = ['signed-out', 'signing-in', 'connected', 'disconnected', 'connecting', 'error', 'empty', 'device-detail', 'offline-detail', 'account', 'settings']
const browser = await chromium.launch({ headless: true })
const errors = []
const measurements = []
const checks = []
try {
  const context = await browser.newContext({ viewport: { width: 440, height: 800 }, deviceScaleFactor: 2, reducedMotion: 'reduce', permissions: ['clipboard-read', 'clipboard-write'] })
  const page = await context.newPage()
  page.on('pageerror', error => errors.push(error.message))
  async function openState(state) {
    await page.goto(`${base}#${state}`)
    await page.reload()
  }
  for (const theme of ['light', 'dark']) {
    await page.emulateMedia({ colorScheme: theme })
    for (const state of states) {
      await openState(state)
      const popup = page.locator('.popover')
      await expect(popup).toBeVisible()
      await expect(page.locator('#review-state')).toHaveValue(state)
      await page.evaluate(() => document.fonts.ready)
      // Move the pointer outside the window so the captured rows aren't hovered.
      await page.mouse.move(420, 780)
      const bounds = await popup.boundingBox()
      expect(bounds.width).toBe(360)
      expect(bounds.height).toBeLessThanOrEqual(560)
      const horizontalOverflow = await popup.evaluate(el => el.scrollWidth > el.clientWidth)
      expect(horizontalOverflow).toBe(false)
      measurements.push({ state, theme, width: bounds.width, height: bounds.height })
      await popup.screenshot({ path: fileURLToPath(new URL(`${state}-${theme}.png`, shots)), animations: 'disabled', scale: 'device' })
    }
  }
  checks.push('22 state/appearance screenshots at 2x; width 360, height ≤560, no horizontal overflow')

  await openState('connected')
  await page.getByRole('button', { name: 'Copy Mesh IP for homelab: 100.96.0.10', exact: true }).click()
  await expect(page.getByRole('status')).toContainText('Copied 100.96.0.10')
  expect(await page.evaluate(() => navigator.clipboard.readText())).toBe('100.96.0.10')
  await page.getByRole('button', { name: 'Dismiss', exact: true }).click()
  await page.getByRole('button', { name: 'Device actions for homelab', exact: true }).click()
  await page.getByRole('button', { name: 'Copy name: homelab.mesh', exact: true }).click()
  expect(await page.evaluate(() => navigator.clipboard.readText())).toBe('homelab.mesh')
  await page.getByRole('button', { name: 'SSH in Terminal', exact: true }).click()
  await expect(page.getByRole('status')).toContainText('Preview: SSH in Terminal requested.')
  checks.push('IP and DNS clipboard values, accessible copy feedback, simulated SSH action')

  await openState('connected')
  await page.getByRole('button', { name: 'Device actions for pixel-9', exact: true }).click()
  await expect(page.getByRole('button', { name: 'SSH in Terminal', exact: true })).toBeDisabled()
  await openState('offline-detail')
  await expect(page.getByRole('button', { name: 'SSH in Terminal', exact: true })).toBeDisabled()
  await expect(page.locator('.last-seen')).toHaveText('Last seen 3 days ago')
  checks.push('SSH unavailable for phone and offline devices; readable last seen')

  await openState('connected')
  await page.getByRole('button', { name: 'Disconnect', exact: true }).click()
  await expect(page.getByRole('heading', { name: 'Disconnected', exact: true })).toBeVisible()
  await page.getByRole('button', { name: 'Device actions for homelab', exact: true }).click()
  await expect(page.getByRole('button', { name: 'SSH in Terminal', exact: true })).toBeDisabled()
  await page.getByRole('button', { name: 'Devices', exact: true }).click()
  await page.getByRole('button', { name: 'Connect', exact: true }).click()
  await expect(page.getByRole('heading', { name: 'Connecting', exact: true })).toBeVisible()
  await page.getByRole('button', { name: 'Cancel', exact: true }).click()
  await expect(page.getByRole('heading', { name: 'Disconnected', exact: true })).toBeVisible()
  await page.waitForTimeout(1400)
  await expect(page.getByRole('heading', { name: 'Disconnected', exact: true })).toBeVisible()
  await page.getByRole('button', { name: 'Connect', exact: true }).click()
  await expect(page.getByRole('heading', { name: 'Connected', exact: true })).toBeVisible()
  checks.push('Disconnect, cancellable Connect, stale completion ignored, successful reconnect')

  await openState('signed-out')
  await page.getByRole('button', { name: 'Sign in with Cloudflare', exact: true }).click()
  await expect(page.getByText('Waiting for browser', { exact: true })).toBeVisible()
  await page.getByRole('button', { name: 'Open browser again', exact: true }).click()
  await page.getByRole('button', { name: 'Cancel', exact: true }).click()
  await expect(page.getByRole('button', { name: 'Sign in with Cloudflare', exact: true })).toBeVisible()
  await page.getByRole('button', { name: 'Sign in with Cloudflare', exact: true }).click()
  await page.getByRole('button', { name: 'Complete sign-in (mock)', exact: true }).click()
  await expect(page.getByRole('heading', { name: 'Connected', exact: true })).toBeVisible()
  await page.getByRole('button', { name: 'Account and sign out', exact: true }).click()
  await page.getByRole('button', { name: 'Sign out', exact: true }).click()
  await expect(page.getByRole('button', { name: 'Sign in with Cloudflare', exact: true })).toBeVisible()
  checks.push('Browser waiting, retry, cancel, sign-in completion, account sign-out')

  await openState('empty')
  await page.getByRole('button', { name: 'Copy command', exact: true }).click()
  expect(await page.evaluate(() => navigator.clipboard.readText())).toBe('meshscale up')
  await openState('settings')
  const preference = page.getByRole('checkbox', { name: 'Launch at login' })
  await expect(preference).toBeChecked()
  await preference.uncheck()
  await expect(preference).not.toBeChecked()
  checks.push('Empty-network command copy and launch-at-login preference')

  await openState('connected')
  await page.keyboard.press('Tab')
  const focus = await page.evaluate(() => ({ tag: document.activeElement.tagName, outline: getComputedStyle(document.activeElement).outlineStyle, width: getComputedStyle(document.activeElement).outlineWidth }))
  expect(focus.tag).toBe('BUTTON')
  expect(focus.outline).toBe('solid')
  expect(focus.width).toBe('3px')
  await page.keyboard.press('ArrowDown')
  await expect(page.getByRole('button', { name: 'Disconnect', exact: true })).toBeFocused()
  await page.getByRole('button', { name: 'Device actions for homelab', exact: true }).focus()
  await page.keyboard.press('Enter')
  await expect(page.getByRole('heading', { name: 'homelab', exact: true })).toBeFocused()
  await page.keyboard.press('Escape')
  await expect(page.getByRole('heading', { name: 'Connected', exact: true })).toBeVisible()
  await openState('connecting')
  expect(await page.locator('.spinner').evaluate(el => getComputedStyle(el).animationName)).toBe('none')
  checks.push('Tab/arrow/Enter/Escape keyboard navigation, visible focus, reduced motion')

  await page.setViewportSize({ width: 320, height: 720 })
  await openState('connected')
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true)
  await page.setViewportSize({ width: 440, height: 800 })
  checks.push('320px narrow viewport fits without horizontal scrolling')

  // Test the self-contained file with networking disabled, not just the dev module graph.
  const standalone = await context.newPage()
  standalone.on('pageerror', error => errors.push(error.message))
  const requests = []
  await standalone.route('http**/*', route => { requests.push(route.request().url()); return route.abort() })
  await standalone.goto(new URL('preview.html', root).href + '#connected')
  await expect(standalone.getByRole('heading', { name: 'Connected', exact: true })).toBeVisible()
  await expect(standalone.locator('#review-state')).toBeVisible()
  expect(requests).toEqual([])
  await standalone.locator('#review-state').selectOption('error')
  await expect(standalone.getByRole('heading', { name: 'Cannot reach Cloudflare', exact: true })).toBeVisible()
  checks.push('Standalone file opens over file://, state controls work, no HTTP requests')

  // A native adapter may reject any action. Ensure failures stay visible.
  const native = await context.newPage()
  await native.addInitScript(() => {
    const data = {
      auth: 'signed-in', connection: { state: 'connected' },
      devices: [{ id: 'mac', kind: 'device', name: 'macbook-air', ipv4: '100.96.0.2', online: true, this_machine: true }],
      sshDeviceIds: [], updatedAt: new Date().toISOString(), preferences: { launchAtLogin: false },
    }
    window.meshscaleBridge = {
      getStatus: async () => data, onChange: () => () => {},
      copy: async () => { throw new Error('Clipboard access denied. Try again.') },
      setLaunchAtLogin: async () => { throw new Error('Could not change launch at login. Try again.') },
    }
  })
  await native.goto(base)
  await native.getByRole('button', { name: 'Copy Mesh IP for macbook-air: 100.96.0.2', exact: true }).click()
  await expect(native.getByRole('status')).toContainText('Clipboard access denied. Try again.')
  await native.getByRole('button', { name: 'Dismiss', exact: true }).click()
  await native.getByRole('button', { name: 'Settings', exact: true }).click()
  await native.getByRole('checkbox', { name: 'Launch at login' }).click()
  await expect(native.getByRole('status')).toContainText('Could not change launch at login. Try again.')
  await expect(native.getByRole('checkbox', { name: 'Launch at login' })).not.toBeChecked()
  checks.push('Native injection overrides mock; clipboard/preference failures display, preference rolls back')

  expect(errors).toEqual([])
  const report = { generatedAt: new Date().toISOString(), deviceScaleFactor: 2, checks, measurements, browserErrors: errors }
  await writeFile(new URL('verification.json', shots), JSON.stringify(report, null, 2) + '\n')
  console.log(JSON.stringify({ screenshots: measurements.length, checks, browserErrors: errors }, null, 2))
} finally { await browser.close() }
