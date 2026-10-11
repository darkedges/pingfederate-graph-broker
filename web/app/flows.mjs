export const flowTabs = [
  { id: 'inbound', label: 'Entra ID → PingFederate', hash: 'entra-first' },
  { id: 'outbound', label: 'PingFederate → Entra ID', hash: 'connections' },
];

export function resolveFlow(hash, previous) {
  if (['entra-first', 'token-exchange'].includes(hash)) return 'inbound';
  if (['connections', 'delegation', 'explorer', 'pf-to-entra'].includes(hash)) return 'outbound';
  return previous === 'outbound' ? 'outbound' : 'inbound';
}
