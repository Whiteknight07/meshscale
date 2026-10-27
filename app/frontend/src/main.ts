import './style.css'
import { readStatus, unavailableBridge, type AppStatus, type MeshDevice } from './bridge'
import { createMock, states, type ReviewState } from './mock'
import { icon } from './icons'

const app = document.querySelector<HTMLElement>('#app')!
const review = import.meta.env.DEV || window.__MESHSCALE_REVIEW__ === true || new URLSearchParams(location.search).get('review') === '1'
const mock = review && !window.meshscaleBridge ? createMock() : undefined
const bridge = window.meshscaleBridge ?? mock ?? unavailableBridge()
let status: AppStatus | undefined
let screen: 'devices' | 'detail' | 'account' | 'settings' = 'devices'
let selectedID = 'node-homelab'
let notice = ''
let noticeError = false
let noticeTimer: ReturnType<typeof setTimeout>
let requestBusy = false
let receivedEvent = false
let destroyed = false

const escape = (value: string) => value.replace(/[&<>"']/g, ch => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[ch]!)
const button = (action: string, label: string, cls = '', attrs = '') => `<button type="button" class="${cls}" data-action="${action}" data-key="${action}" ${attrs}>${label}</button>`
const deviceIcon = (d: MeshDevice) => icon(/android|ios|phone/i.test(d.os || '') ? 'phone' : d.kind === 'node' ? 'server' : 'laptop')
const address = (d: MeshDevice) => d.ipv4 || d.ipv6 || ''
const connected = () => status?.connection.state === 'connected'
function lastSeen(d: MeshDevice): string {
  if (!d.last_seen_at) return 'Last seen unknown'
  const time = Date.parse(d.last_seen_at)
  if (!Number.isFinite(time)) return 'Last seen unknown'
  const age = Math.max(0, Date.parse(mock ? '2026-10-26T12:00:00Z' : new Date().toISOString()) - time)
  if (age < 60_000) return 'Last seen just now'
  if (age < 3_600_000) { const n = Math.floor(age / 60_000); return `Last seen ${n} ${n === 1 ? 'minute' : 'minutes'} ago` }
  if (age < 86_400_000) { const n = Math.floor(age / 3_600_000); return `Last seen ${n} ${n === 1 ? 'hour' : 'hours'} ago` }
  const n = Math.floor(age / 86_400_000)
  return `Last seen ${n} ${n === 1 ? 'day' : 'days'} ago`
}
function copyButton(value: string, label: string, cls = ''): string {
  return `<button type="button" class="${cls}" data-copy="${escape(value)}" data-key="copy-${escape(value)}" aria-label="${escape(label)}" title="${escape(label)}">${escape(value)}${icon('copy')}</button>`
}
function header(): string {
  return `<header class="header"><div class="brand">${icon(connected() ? 'mesh' : 'broken')}<span>meshscale</span></div>${status?.auth === 'signed-in' ? button('settings', icon('settings'), 'icon-button', 'aria-label="Settings" title="Settings"') : ''}</header>`
}
function footer(): string {
  if (status?.auth !== 'signed-in') return `<footer class="footer signed-out-footer"><span>Private network for your devices</span>${button('quit', 'Quit', 'quiet')}</footer>`
  const account = status.account
  return `<footer class="footer">${screen === 'account'
    ? '<span class="footer-note">Signed in with Cloudflare</span>'
    : button('account', `<span class="account-copy"><span>${escape(account?.email || 'Cloudflare account')}</span><span class="secondary">${escape(account?.name || 'Account details unavailable')}</span></span>${icon('chevron')}`, 'account-button', 'aria-label="Account and sign out"')}${button('quit', 'Quit', 'quiet')}</footer>`
}
function connection(): string {
  const state = status!.connection.state
  const labels = { connected: 'Connected', disconnected: 'Disconnected', connecting: 'Connecting', error: 'Connection failed' }
  const descriptions = { connected: 'via Cloudflare', disconnected: 'This device is off the mesh', connecting: 'Connecting to Cloudflare…', error: 'This device is off the mesh' }
  return `<section class="connection" aria-label="Connection"><div class="connection-mark ${state === 'connected' ? 'is-online' : ''}">${state === 'connecting' ? '<span class="spinner" aria-hidden="true"></span>' : icon(state === 'connected' ? 'mesh' : 'broken')}</div><div class="connection-copy"><h1>${labels[state]}</h1><p>${descriptions[state]}</p></div>${button(state === 'connected' || state === 'connecting' ? 'disconnect' : 'connect', state === 'connected' ? 'Disconnect' : state === 'connecting' ? 'Cancel' : 'Connect', state === 'connected' || state === 'connecting' ? 'small-button' : 'small-button primary', requestBusy && state !== 'connecting' ? 'disabled' : '')}</section>`
}
function deviceRow(d: MeshDevice, local = false): string {
  const ip = address(d)
  const online = local ? connected() : d.online
  const detailKey = `device-${d.id}`
  return `<li class="device-row ${!online ? 'offline' : ''}">
    <div class="device-icon">${deviceIcon(d)}</div>
    <div class="device-info">
      <button type="button" class="device-name" data-device="${escape(d.id)}" data-key="${escape(detailKey)}" aria-label="Device actions for ${escape(d.name)}">${escape(d.name)}</button>
      ${!d.online && !local ? `<span class="device-meta">${escape(lastSeen(d))}</span>` : ip ? copyButton(ip, `Copy Mesh IP for ${d.name}: ${ip}`, 'ip-copy') : '<span class="device-meta">No Mesh IP assigned</span>'}
    </div>
    <div class="device-tail">${local ? '<span class="local-label">This Mac</span>' : `<span class="online-label ${d.online ? 'is-online' : ''}"><span class="dot"></span>${d.online ? 'Online' : 'Offline'}</span>`}<button type="button" class="detail-button" data-device="${escape(d.id)}" data-key="detail-${escape(d.id)}" aria-label="Open ${escape(d.name)} details">${icon('chevron')}</button></div>
  </li>`
}
function inventory(): string {
  const local = status!.devices.find(d => d.this_machine)
  const others = status!.devices.filter(d => !d.this_machine)
  const online = others.filter(d => d.online).length
  const stale = !connected()
  return `${connection()}<div class="inventory scroll-area">
    ${status!.error ? `<section class="error-message" role="alert">${icon('alert')}<div><h2>${escape(status!.error.message)}</h2><p>${escape(status!.error.recovery)}</p></div></section>` : ''}
    <section class="local-section" aria-label="This device"><div class="section-label">This device</div>${local ? `<ul class="device-list">${deviceRow(local, true)}</ul>` : '<p class="missing-device">This Mac has no Mesh IP yet.</p>'}</section>
    ${others.length ? `<section class="other-section" aria-label="Other devices"><div class="section-heading"><h2>Other devices</h2><span>${stale ? 'Last known status' : `${online} online`}</span></div><ul class="device-list">${others.map(d => deviceRow(d)).join('')}</ul></section>` : emptyNetwork()}
  </div>`
}
function emptyNetwork(): string {
  return `<section class="empty-network"><h2>Add another device</h2><p>On another Linux device with meshscale installed and signed in, run:</p><div class="command"><code>meshscale up</code>${button('copy-command', icon('copy'), 'icon-button', 'aria-label="Copy command" title="Copy command"')}</div><p class="secondary">It will appear here when it connects.</p></section>`
}
function authentication(): string {
  const waiting = status!.auth === 'signing-in'
  return `<section class="auth-content"><div class="auth-symbol">${waiting ? '<span class="spinner" aria-hidden="true"></span>' : icon('mesh')}</div><h1>${waiting ? 'Sign in with Cloudflare' : 'Your devices, connected'}</h1><p>${waiting ? 'Finish signing in in your browser, then come back here.' : 'Connect your devices by signing in to Cloudflare in your browser.'}</p>${waiting
    ? `<div class="waiting-status"><span class="dot"></span>Waiting for browser</div><div class="auth-actions">${button('sign-in', 'Open browser again', 'small-button')}${button('cancel-sign-in', 'Cancel', 'quiet')}</div>`
    : button('sign-in', `${icon('cloud')}Sign in with Cloudflare`, 'primary sign-in', requestBusy ? 'disabled' : '')}</section>`
}
function back(title = 'Devices'): string {
  return `<nav class="back-nav" aria-label="Back">${button('back', `${icon('back')}${title}`, 'back-button')}</nav>`
}
function copyAction(label: string, value?: string): string {
  const content = `<span>${icon('copy')}${label}</span><span class="${value ? 'value-button' : 'secondary'}">${value ? escape(value) : 'Not assigned'}</span>`
  return value
    ? `<button type="button" class="action-row" data-copy="${escape(value)}" data-key="copy-${escape(value)}" aria-label="${label}: ${escape(value)}">${content}</button>`
    : `<div class="action-row">${content}</div>`
}
function detail(): string {
  const d = status!.devices.find(device => device.id === selectedID)
  if (!d) return `${back()}<section class="pane"><h1>Device no longer available</h1><p>Return to your devices to see the current list.</p></section>`
  const ip = address(d)
  const online = d.this_machine ? connected() : d.online
  const canSSH = connected() && d.online && !d.this_machine && status!.sshDeviceIds.includes(d.id)
  const os = ({ mac: 'macOS', linux: 'Linux', android: 'Android', ios: 'iOS', windows: 'Windows' } as Record<string, string>)[d.os || ''] || d.os || 'Device'
  const reason = d.this_machine ? 'This is the device you’re using.' : !d.online ? 'This device is offline. Connect it to use SSH.' : !connected() ? 'Connect this Mac to use SSH.' : !status!.sshDeviceIds.includes(d.id) ? 'SSH is not enabled on this device.' : ''
  return `${back()}<section class="detail-summary"><div class="detail-device-icon">${deviceIcon(d)}</div><div><h1 tabindex="-1" data-key="screen-title" data-screen-title>${escape(d.name)}</h1><span class="secondary">${escape(os)}</span></div><span class="online-label ${online ? 'is-online' : ''}"><span class="dot"></span>${online ? 'Online' : 'Offline'}</span></section><p class="last-seen">${escape(lastSeen(d))}</p>
    <section class="action-list" aria-label="Device actions">
      ${copyAction('Copy Mesh IP', ip)}
      ${copyAction('Copy name', d.dns_name)}
      ${button('ssh', `<span>${icon('terminal')}SSH in Terminal</span>${icon('external')}`, 'ssh-action', `${canSSH ? '' : 'disabled aria-describedby="ssh-reason"'}`)}
    </section>${reason ? `<p class="action-note" id="ssh-reason">${escape(reason)}</p>` : '<p class="action-note">Open a keyless SSH session on this device.</p>'}`
}
function accountScreen(): string {
  return `${back()}<section class="pane account-pane"><h1 tabindex="-1" data-key="screen-title" data-screen-title>Account</h1><p class="account-email">${escape(status!.account?.email || 'Email unavailable')}</p><p class="secondary">${escape(status!.account?.name || 'Account unavailable')}</p><div class="account-provider">${icon('cloud')}Signed in with Cloudflare</div><p class="account-explanation">Sign out disconnects this Mac from your mesh.</p>${button('sign-out', `${icon('signout')}Sign out`, 'small-button sign-out', requestBusy ? 'disabled' : '')}</section>`
}
function settingsScreen(): string {
  return `${back()}<section class="pane settings-pane"><h1 tabindex="-1" data-key="screen-title" data-screen-title>Settings</h1><label class="preference"><input type="checkbox" id="launch-at-login" data-key="launch-at-login" ${status!.preferences.launchAtLogin ? 'checked' : ''}><span>Launch at login<span class="secondary">Keep meshscale in your menu bar.</span></span></label></section>`
}
function render(): void {
  if (destroyed) return
  const key = (document.activeElement as HTMLElement | null)?.dataset.key
  if (!status) { app.innerHTML = '<section class="popover loading" aria-label="meshscale"><p>Loading meshscale…</p></section>'; return }
  if (status.auth !== 'signed-in') screen = 'devices'
  const isAuth = status.auth !== 'signed-in'
  const content = isAuth ? authentication() : screen === 'devices' ? inventory() : screen === 'detail' ? detail() : screen === 'account' ? accountScreen() : settingsScreen()
  app.innerHTML = `<section class="popover ${isAuth ? 'auth-window' : screen === 'devices' ? 'devices-window' : 'inner-window'}" aria-label="meshscale" data-state="${status.connection.state}">${header()}<div class="window-body">${content}</div>${footer()}<div class="feedback ${notice ? 'visible' : ''} ${noticeError ? 'feedback-error' : ''}" role="status" aria-live="polite" aria-atomic="true">${notice ? `${icon(noticeError ? 'alert' : 'check')}<span>${escape(notice)}</span>${button('dismiss-notice', 'Dismiss', 'feedback-dismiss')}` : ''}</div></section>`
  if (key) app.querySelector<HTMLElement>(`[data-key="${CSS.escape(key)}"]`)?.focus({ preventScroll: true })
  updateReviewControls()
}
function notify(message: string, error = false): void {
  clearTimeout(noticeTimer)
  notice = message
  noticeError = error
  render()
  if (!error) noticeTimer = setTimeout(() => { notice = ''; render() }, 4000)
}
function navigate(next: typeof screen): void {
  const previous = screen
  notice = ''
  screen = next
  render()
  const target = next === 'devices' && previous === 'detail'
    ? app.querySelector<HTMLElement>(`[data-key="device-${CSS.escape(selectedID)}"]`)
    : app.querySelector<HTMLElement>('[data-screen-title]') ?? app.querySelector<HTMLElement>('[data-action="back"]') ?? app.querySelector<HTMLElement>('[data-action="settings"]')
  target?.focus()
}
async function perform(action: () => Promise<void>, success?: string, allowConcurrent = false): Promise<void> {
  if (requestBusy && !allowConcurrent) return
  requestBusy = true
  try {
    await action()
    if (success) notify(success)
  } catch (error) {
    notify(error instanceof Error ? error.message : 'The action failed. Try again.', true)
  } finally { requestBusy = false; render() }
}
app.addEventListener('click', event => {
  const target = (event.target as Element).closest<HTMLElement>('button')
  if (!target || (target as HTMLButtonElement).disabled) return
  if (target.dataset.device) {
    selectedID = target.dataset.device
    navigate('detail')
    return
  }
  if (target.dataset.copy !== undefined) {
    void perform(() => bridge.copy(target.dataset.copy!), `Copied ${target.dataset.copy}`)
    return
  }
  const action = target.dataset.action
  if (action === 'settings' || action === 'account') { navigate(action); return }
  if (action === 'back') { navigate('devices'); return }
  if (action === 'dismiss-notice') { notice = ''; render(); return }
  if (action === 'connect') void perform(() => bridge.connect())
  if (action === 'disconnect') void perform(() => bridge.disconnect(), undefined, true)
  if (action === 'sign-in') void perform(() => bridge.signIn())
  if (action === 'cancel-sign-in') void perform(() => bridge.cancelSignIn())
  if (action === 'sign-out') void perform(() => bridge.signOut())
  if (action === 'copy-command') void perform(() => bridge.copy('meshscale up'), 'Copied command')
  if (action === 'ssh') {
    const d = status!.devices.find(device => device.id === selectedID)
    if (d) void perform(() => bridge.openSSH(d), mock ? 'Preview: SSH in Terminal requested.' : 'Opened SSH in Terminal')
  }
  if (action === 'quit') void perform(() => bridge.quit(), mock ? 'Preview: Quit requested.' : undefined)
})
app.addEventListener('change', event => {
  if ((event.target as HTMLElement).id === 'launch-at-login') {
    const checked = (event.target as HTMLInputElement).checked
    void perform(() => bridge.setLaunchAtLogin(checked), checked ? 'Launch at login enabled' : 'Launch at login disabled')
  }
})
app.addEventListener('keydown', event => {
  if (event.key === 'Escape') {
    if (notice) { notice = ''; render() }
    else if (screen !== 'devices') navigate('devices')
  }
  // Native-menu convenience: up/down traverse actionable rows; Tab also works.
  if ((event.key === 'ArrowDown' || event.key === 'ArrowUp') && !(event.target instanceof HTMLInputElement)) {
    const controls = [...app.querySelectorAll<HTMLElement>('button:not(:disabled), input:not(:disabled)')]
    const index = controls.indexOf(document.activeElement as HTMLElement)
    const direction = event.key === 'ArrowDown' ? 1 : -1
    controls[(index + direction + controls.length) % controls.length]?.focus()
    event.preventDefault()
  }
})

let reviewPanel: HTMLElement | undefined
function updateReviewControls(): void {
  if (!reviewPanel) return
  const complete = reviewPanel.querySelector<HTMLButtonElement>('[data-complete]')!
  complete.hidden = status?.auth !== 'signing-in'
}
function applyHash(): void {
  if (!mock) return
  const hash = location.hash.slice(1)
  const state = states.includes(hash as ReviewState) ? hash as ReviewState : 'connected'
  screen = state === 'device-detail' || state === 'offline-detail' ? 'detail' : state === 'account' || state === 'settings' ? state : 'devices'
  selectedID = state === 'offline-detail' ? 'reg-thinkpad' : 'node-homelab'
  notice = ''
  requestBusy = false
  clearTimeout(noticeTimer)
  mock.setState(state)
  if (reviewPanel) reviewPanel.querySelector<HTMLSelectElement>('#review-state')!.value = state
}
if (review) {
  document.body.classList.add('review')
  reviewPanel = document.createElement('aside')
  reviewPanel.className = 'review-controls'
  reviewPanel.setAttribute('aria-label', 'Development review controls')
  reviewPanel.innerHTML = `<span class="review-label">Design review${mock ? ' / mock data' : ' / native bridge'}</span><div class="review-fields"><label>State<select id="review-state" ${mock ? '' : 'disabled'}>${states.map(state => `<option value="${state}">${state}</option>`).join('')}</select></label><label>Appearance<select id="review-theme"><option value="system">System</option><option value="light">Light</option><option value="dark">Dark</option></select></label></div><button type="button" data-complete hidden>Complete sign-in (mock)</button><p>Device IPs copy to your clipboard. Browser, SSH and Quit are simulated.</p>`
  document.body.append(reviewPanel)
  reviewPanel.querySelector('#review-state')!.addEventListener('change', event => { location.hash = (event.target as HTMLSelectElement).value })
  reviewPanel.querySelector('#review-theme')!.addEventListener('change', event => {
    const theme = (event.target as HTMLSelectElement).value
    if (theme === 'system') delete document.documentElement.dataset.theme
    else document.documentElement.dataset.theme = theme
  })
  reviewPanel.querySelector('[data-complete]')!.addEventListener('click', () => { mock?.completeSignIn(); location.hash = 'connected' })
  window.addEventListener('hashchange', applyHash)
}
const unsubscribe = bridge.onChange(value => { receivedEvent = true; status = readStatus(value); render() })
render()
if (mock) applyHash()
else bridge.getStatus().then(value => { if (!receivedEvent && !destroyed) { status = readStatus(value); render() } }).catch(error => {
  if (receivedEvent || destroyed) return
  status = { auth: 'signed-in', connection: { state: 'error' }, devices: [], sshDeviceIds: [], updatedAt: new Date().toISOString(), preferences: { launchAtLogin: false }, error: { code: 'status-unavailable', message: 'Cannot read connection status', recovery: error instanceof Error ? error.message : 'Quit and reopen meshscale.' } }
  render()
})
window.addEventListener('pagehide', () => { destroyed = true; clearTimeout(noticeTimer); unsubscribe() }, { once: true })
