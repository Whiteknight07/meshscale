import { rulePrefix, ruleMarker, dnsPrefix, dnsMarker } from './markers.ts';
import { activityLabel, viewFromHash } from './browser-view.ts';
import { Effect } from 'effect';
import { FetchHttpClient } from 'effect/http';
import { HttpApiClient } from 'effect/http-api';
import { ConsoleApi } from './api.ts';
import type { Action, Machine, Preview, Snapshot } from './model.ts';

const element = (id: string) => {
  const el = document.getElementById(id);
  if (!el) throw new Error(`Missing UI element ${id}`);
  return el;
};
const input = (id: string) => {
  const el = element(id);
  if (!(el instanceof HTMLInputElement)) throw new Error('Expected input');
  return el;
};
const button = (id: string) => {
  const el = element(id);
  if (!(el instanceof HTMLButtonElement)) throw new Error('Expected button');
  return el;
};
const dialog = (id: string) => {
  const el = element(id);
  if (!(el instanceof HTMLDialogElement)) throw new Error('Expected dialog');
  return el;
};
const escape = (s: string) =>
  s.replace(
    /[&<>"']/g,
    (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c] ?? c,
  );
const connection = (m: Machine) =>
  `<span class="${m.online ? 'online' : 'offline'}"><span class="dot"></span>${m.online ? 'Online' : 'Offline'}</span><span class="subline">${escape(activityLabel(m.lastSeen, m.online))}</span>`;
const machineKey = (m: Machine) => `${m.kind}/${m.id}`;
const client = HttpApiClient.make(ConsoleApi, { baseUrl: location.origin });
const request = <A, E>(f: (api: HttpApiClient.ForApi<typeof ConsoleApi>) => Effect.Effect<A, E>) =>
  client.pipe(Effect.flatMap(f), Effect.provide(FetchHttpClient.layer));
let snapshot: Snapshot | undefined;
let view = viewFromHash(location.hash);
let policy = '';
let pending: { action: Action; preview: Preview } | undefined;
let busy = false;
const report = (message: string, error = false) => {
  const el = element('status');
  el.textContent = message;
  el.className = error ? 'error' : 'muted';
};
const run = <A, E>(effect: Effect.Effect<A, E>, onSuccess?: (value: A) => void) => {
  void Effect.runPromise(
    effect.pipe(
      Effect.tap((value) => Effect.sync(() => onSuccess?.(value))),
      Effect.catch((error) =>
        Effect.sync(() => {
          report(
            error instanceof Error ? error.message : 'The request failed. Refresh and try again.',
            true,
          );
          busy = false;
          button('refresh').disabled = false;
          if (pending) button('apply').disabled = !input('confirm').checked;
        }),
      ),
    ),
  );
};
const table = (head: string, body: string) =>
  `<div class="table-scroll"><table><thead><tr>${head}</tr></thead><tbody>${body}</tbody></table></div>`;
const ruleRows = () =>
  snapshot?.rules
    .filter((r) => r.name.startsWith(rulePrefix) && r.description?.startsWith(ruleMarker))
    .sort((a, b) => a.precedence - b.precedence)
    .map(
      (r) =>
        `<tr><td>${escape(r.name.slice(rulePrefix.length))}<span class="subline">Priority ${r.precedence}</span></td><td><span class="tag">${escape(r.action)}</span></td><td class="rule-expression">${escape(r.traffic ?? '')}</td></tr>`,
    )
    .join('') ?? '';
const render = () => {
  const data = snapshot;
  if (!data) return;
  const machines = data.machines;
  const content = element('content');
  content.setAttribute('aria-busy', 'false');
  element('machine-count').textContent = String(machines.length);
  element('freshness').textContent =
    `Cloudflare inventory · ${new Date(data.fetchedAt).toLocaleTimeString()}`;
  element('warnings').innerHTML = data.warnings
    .map((w) => `<div class="notice">${escape(w)}</div>`)
    .join('');
  const copy = {
    machines: ['Machines', 'Every machine in your private network.'],
    rules: ['Access rules', 'Choose who can reach what. Review every change before it goes live.'],
    dns: ['DNS names', 'Private names, backed by your account’s Gateway DNS overrides.'],
    exits: [
      'Exit nodes',
      'Secure machines that offer an internet connection to your other devices.',
    ],
  };
  const selected = Object.entries(copy).find(([key]) => key === view)?.[1] ?? copy.machines;
  element('title').textContent = selected[0] ?? 'Machines';
  element('subtitle').textContent = selected[1] ?? '';
  document.querySelectorAll<HTMLAnchorElement>('nav a').forEach((a) => {
    a.setAttribute('aria-current', a.dataset.view === view ? 'page' : 'false');
  });
  if (view === 'machines') {
    const stats = `<div class="stats"><div><strong>${machines.length}</strong><span>machines</span></div><div><strong>${machines.filter((m) => m.online).length}</strong><span>online</span></div><div><strong>${machines.filter((m) => m.secure).length}</strong><span>secure</span></div></div>`;
    content.innerHTML =
      stats +
      (machines.length
        ? table(
            '<th>Machine</th><th>Mesh IP</th><th class="optional">Owner</th><th>Connection</th><th class="optional-mobile">Capabilities</th>',
            machines
              .map(
                (m) =>
                  `<tr><td><button class="machine-name" data-machine="${escape(machineKey(m))}">${escape(m.name || 'Unnamed machine')}</button><span class="subline">${escape(m.os || 'Unknown OS')} · ${escape(m.dns)}</span></td><td class="ip">${escape(m.ipv4 || m.ipv6 || 'Address unavailable')}</td><td class="optional">${escape(m.owner || 'Not reported')}</td><td>${connection(m)}</td><td class="optional-mobile">${m.secure ? '<span class="tag">Secure</span>' : ''}${m.offersExit ? '<span class="tag">Exit node</span>' : ''}<span class="subline">SSH: ${escape(m.ssh)}</span></td></tr>`,
              )
              .join(''),
          )
        : '<p class="empty">No machines yet. Run <code>meshscale up</code> on a device to join.</p>');
    document.querySelectorAll<HTMLButtonElement>('[data-machine]').forEach((el) => {
      el.addEventListener('click', () => {
        const m = machines.find((m) => machineKey(m) === el.dataset.machine);
        if (m) showMachine(m);
      });
    });
  } else if (view === 'rules') {
    content.innerHTML = `<div class="notice">Gateway stores compiled rules, while the CLI keeps the original <code>rules.json</code> locally. ${policy ? 'The editor contains the last policy saved by this console.' : 'Paste your CLI policy to edit it here. No policy is inferred from compiled rules.'} Keep CLI files in sync after applying.</div><label for="policy-editor" class="eyebrow">POLICY JSON</label><textarea id="policy-editor" class="editor" spellcheck="false" placeholder='{"groups":{"admins":["you@example.com"]},"rules":[{"from":["group:admins"],"to":["server:22"]}]'>${escape(policy)}</textarea><div class="actions"><button id="preview-rules" class="primary">Preview rule changes</button></div><h2 class="section-title">Deployed meshscale rules</h2>${ruleRows() ? table('<th>Rule</th><th>Action</th><th>Traffic expression</th>', ruleRows()) : '<p class="muted">No meshscale network rules deployed. Gateway’s default allow behavior applies, subject to other account policies.</p>'}`;
    element('policy-editor').addEventListener('input', (e) => {
      if (e.target instanceof HTMLTextAreaElement) policy = e.target.value;
    });
    button('preview-rules').addEventListener('click', () => {
      previewAction({ type: 'rules', policy });
    });
  } else if (view === 'dns') {
    const records = data.rules.filter(
      (r) => r.name.startsWith(dnsPrefix) && r.description?.startsWith(dnsMarker),
    );
    content.innerHTML =
      `<div class="notice">Names below are the actual deployed Gateway rules used by <code>meshscale dns</code>. Open a machine to preview a name change. Gateway propagation may take about 60 seconds.</div>` +
      (records.length
        ? table(
            '<th>Name</th><th>Address</th><th>State</th>',
            records
              .map(
                (r) =>
                  `<tr><td>${escape(r.name.slice(dnsPrefix.length))}</td><td class="ip">${escape(r.rule_settings?.override_ips?.join(', ') ?? '')}</td><td>${r.enabled ? 'Enabled' : 'Disabled'}</td></tr>`,
              )
              .join(''),
          )
        : '<p class="empty">No DNS overrides deployed yet. Run <code>meshscale dns sync --dry-run</code> to preview initial names.</p>');
  } else {
    const exits = machines.filter((m) => m.offersExit);
    content.innerHTML =
      `<div class="notice">Exit capability comes from the validated, owner-bound secure key directory. Selection, advertisement and LAN permissions stay on each device: <code>meshscale exit-node</code>. Online reflects Cloudflare inventory, not a reachability probe from this Worker.</div>` +
      (exits.length
        ? table(
            '<th>Exit node</th><th>Mesh IP</th><th>Owner</th><th>Connection</th>',
            exits
              .map(
                (m) =>
                  `<tr><td>${escape(m.name)}</td><td class="ip">${escape(m.ipv4)}</td><td>${escape(m.owner)}</td><td>${connection(m)}</td></tr>`,
              )
              .join(''),
          )
        : '<p class="empty">No exit nodes advertised.<span class="subline">A Linux secure peer can advertise exit capability from its local CLI.</span></p>');
  }
};
const showMachine = (m: Machine) => {
  element('detail-content').innerHTML =
    `<p class="eyebrow">MACHINE DETAILS</p><h2>${escape(m.name)}</h2><p>${connection(m)}</p><dl class="detail-grid"><dt>Mesh IPv4</dt><dd>${escape(m.ipv4 || 'Not reported')}</dd><dt>Mesh IPv6</dt><dd>${escape(m.ipv6 || 'Not reported')}</dd><dt>Owner</dt><dd>${escape(m.owner || 'Not reported')}</dd><dt>OS</dt><dd>${escape(m.os || 'Unknown')}</dd><dt>Secure mode</dt><dd>${m.secure ? 'Enabled' : 'Not advertised'}</dd><dt>Exit node</dt><dd>${m.offersExit ? 'Advertised' : 'Not advertised'}</dd><dt>SSH mode</dt><dd>${escape(m.ssh)}</dd></dl><label class="field">${m.kind === 'node' ? 'Machine name' : 'DNS alias'}<input id="new-name" type="text" maxlength="63" value="${escape(m.name)}"></label><div class="actions"><button id="rename">Preview name change</button><button id="revoke" class="danger">${m.kind === 'node' ? 'Remove node…' : 'Revoke device…'}</button></div>`;
  button('rename').addEventListener('click', () => {
    previewAction({ type: 'rename', id: machineKey(m), name: input('new-name').value });
  });
  button('revoke').addEventListener('click', () => {
    previewAction({ type: 'revoke', id: machineKey(m) });
  });
  dialog('detail').showModal();
};
const previewAction = (action: Action) => {
  if (busy) return;
  busy = true;
  report('Reading current account state and preparing the diff…');
  run(
    request((api) => api.console.preview({ payload: action })),
    (preview) => {
      busy = false;
      pending = { action, preview };
      element('notice').textContent = preview.notice;
      element('before').textContent = preview.before;
      element('after').textContent = preview.after;
      input('confirm').checked = false;
      button('apply').disabled = true;
      dialog('detail').close();
      dialog('review').showModal();
      report('Diff ready. No changes applied.');
    },
  );
};
const refresh = () => {
  if (busy) return;
  busy = true;
  button('refresh').disabled = true;
  run(
    request((api) => api.console.snapshot()),
    (data) => {
      snapshot = data;
      busy = false;
      button('refresh').disabled = false;
      render();
      report(
        'Inventory loaded. Online means Cloudflare reported activity within five minutes; Mesh nodes use tunnel health.',
      );
    },
  );
};
window.addEventListener('hashchange', () => {
  view = viewFromHash(location.hash);
  render();
});
button('refresh').addEventListener('click', refresh);
button('theme').addEventListener('click', () => {
  const theme =
    document.documentElement.dataset.theme ??
    (matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light');
  document.documentElement.dataset.theme = theme === 'dark' ? 'light' : 'dark';
});
button('close-detail').addEventListener('click', () => {
  dialog('detail').close();
});
button('cancel-review').addEventListener('click', () => {
  pending = undefined;
  dialog('review').close();
});
input('confirm').addEventListener('change', () => {
  button('apply').disabled = busy || !input('confirm').checked;
});
button('apply').addEventListener('click', () => {
  if (busy || !pending || !input('confirm').checked) return;
  busy = true;
  button('apply').disabled = true;
  const { action, preview } = pending;
  run(
    request((api) =>
      api.console.apply({ payload: { action, fingerprint: preview.fingerprint, confirm: true } }),
    ),
    (data) => {
      busy = false;
      pending = undefined;
      dialog('review').close();
      report(data.message);
      refresh();
    },
  );
});
view = viewFromHash(location.hash);
run(
  request((api) => api.console.policy()),
  (saved) => {
    policy = saved?.json ?? '';
    if (view === 'rules') render();
  },
);
refresh();
