export const viewFromHash = (hash: string) => {
  const value = hash.slice(1);
  return value === 'rules' || value === 'dns' || value === 'exits' ? value : 'machines';
};

export const activityLabel = (lastSeen: string | null, online: boolean, now = Date.now()) => {
  if (!lastSeen || !Number.isFinite(Date.parse(lastSeen))) return online ? 'Active' : 'Never seen';
  const ms = now - Date.parse(lastSeen);
  if (ms < 60000) return 'Seen just now';
  if (ms < 3600000) return `Seen ${Math.floor(ms / 60000)}m ago`;
  if (ms < 86400000) return `Seen ${Math.floor(ms / 3600000)}h ago`;
  return `Seen ${Math.floor(ms / 86400000)}d ago`;
};
