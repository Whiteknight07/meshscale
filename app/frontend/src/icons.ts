// All icons are local SVG; no icon font, remote asset, or platform dependency.
export function icon(name: string, className = ''): string {
  const paths: Record<string, string> = {
    mesh: '<rect x="3" y="3" width="5" height="5" rx="1.4"/><rect x="16" y="3" width="5" height="5" rx="1.4"/><rect x="16" y="16" width="5" height="5" rx="1.4"/><path d="M8 5.5h8M5.5 8v8a2.5 2.5 0 0 0 2.5 2.5h8"/>',
    broken: '<rect x="3" y="3" width="5" height="5" rx="1.4"/><rect x="16" y="3" width="5" height="5" rx="1.4"/><rect x="16" y="16" width="5" height="5" rx="1.4"/><path d="M8 5.5h2m4 0h2M5.5 8v8a2.5 2.5 0 0 0 2.5 2.5h2m4 0h2"/>',
    laptop: '<rect x="4" y="4" width="16" height="12" rx="1.5"/><path d="M2 20h20l-2-4H4l-2 4Z"/>',
    server: '<rect x="4" y="3" width="16" height="18" rx="2"/><path d="M4 9h16M4 15h16M7 6h.01M7 12h.01M7 18h.01M11 6h6M11 12h6M11 18h6"/>',
    phone: '<rect x="6" y="2" width="12" height="20" rx="2.5"/><path d="M10 5h4M11 19h2"/>',
    chevron: '<path d="m10 7 5 5-5 5"/>',
    back: '<path d="m14 6-6 6 6 6"/>',
    copy: '<rect x="8" y="8" width="12" height="13" rx="2"/><path d="M15 8V5a2 2 0 0 0-2-2H5a2 2 0 0 0-2 2v8a2 2 0 0 0 2 2h3"/>',
    terminal: '<rect x="3" y="4" width="18" height="16" rx="2"/><path d="m7 9 3 3-3 3m6 0h4"/>',
    check: '<path d="m5 12 4 4L19 6"/>',
    settings: '<path d="m9 3-.7 2.2-2 .9-2.1-.5-1.5 2.6 1.5 1.7-.2 2.2-1.5 1.6 1.5 2.6 2.2-.5 1.9 1L9 20h3l.8-2.2 1.9-1 2.2.5 1.5-2.6-1.5-1.6-.2-2.2 1.5-1.7-1.5-2.6-2.1.5-2-.9L12 3Z" transform="translate(1 0)"/><circle cx="11.5" cy="11.5" r="3"/>',
    cloud: '<path d="M6 18a4 4 0 0 1-1-7.9 6 6 0 0 1 11.5-1.7A4.8 4.8 0 1 1 18 18H6Z"/>',
    alert: '<path d="m10.3 4-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.7-3l-8-14a2 2 0 0 0-3.4 0Z"/><path d="M12 9v5m0 3h.01"/>',
    external: '<path d="M14 3h7v7m0-7L10 14M10 3H5a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-5"/>',
    signout: '<path d="M9 4H5a2 2 0 0 0-2 2v12a2 2 0 0 0 2 2h4m6-12 4 4-4 4m-7-4h11"/>',
  }
  return `<svg class="icon ${className}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${paths[name] || paths.laptop}</svg>`
}
