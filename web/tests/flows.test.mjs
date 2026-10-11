import test from 'node:test';
import assert from 'node:assert/strict';
import { flowTabs, resolveFlow } from '../app/flows.mjs';

test('exactly two distinct flow tabs', () => {
  assert.equal(flowTabs.length, 2);
  assert.deepEqual(flowTabs.map(tab => tab.id), ['inbound', 'outbound']);
});
test('Microsoft callbacks override the previous PF flow', () => {
  for (const hash of ['entra-first', 'token-exchange']) assert.equal(resolveFlow(hash, 'outbound'), 'inbound');
});
test('connection and directory links select only the PF-first flow', () => {
  for (const hash of ['connections', 'delegation', 'explorer', 'pf-to-entra']) assert.equal(resolveFlow(hash, 'inbound'), 'outbound');
});
test('root login callback retains selected direction', () => {
  assert.equal(resolveFlow('', 'outbound'), 'outbound');
  assert.equal(resolveFlow('', 'inbound'), 'inbound');
});
test('unknown selection defaults safely to Microsoft-first', () => {
  assert.equal(resolveFlow('unknown', 'invalid'), 'inbound');
});
