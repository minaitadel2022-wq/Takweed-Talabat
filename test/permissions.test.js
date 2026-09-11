const test = require('node:test');
const assert = require('node:assert/strict');
const {
  ALL_PERMISSION_KEYS, GRANTABLE_PERMISSION_KEYS,
  getEffectivePermissions, hasPermission, sanitizePermissions
} = require('../public/js/permissions');

test('super_admin has every permission regardless of any saved permissions object', () => {
  const user = { role: 'super_admin', permissions: { create_request: false, delete_records: false } };
  for (const key of ALL_PERMISSION_KEYS) {
    assert.equal(hasPermission(user, key), true, `expected super_admin to have ${key}`);
  }
});

test('a fresh admin (no permissions object) gets the admin defaults', () => {
  const user = { role: 'admin' };
  assert.equal(hasPermission(user, 'create_request'), true);
  assert.equal(hasPermission(user, 'edit_request'), true);
  assert.equal(hasPermission(user, 'convert_to_quote'), true);
});

test('a fresh admin does NOT get delete_records by default — it must be granted explicitly', () => {
  assert.equal(hasPermission({ role: 'admin' }, 'delete_records'), false);
});

test('a fresh viewer (no permissions object) has nothing', () => {
  const perms = getEffectivePermissions({ role: 'viewer' });
  for (const key of GRANTABLE_PERMISSION_KEYS) {
    assert.equal(perms[key], false, `expected viewer default for ${key} to be false`);
  }
});

test('an explicit permissions object overrides the role default in both directions', () => {
  const grantedViewer = { role: 'viewer', permissions: { create_request: true } };
  assert.equal(hasPermission(grantedViewer, 'create_request'), true);
  assert.equal(hasPermission(grantedViewer, 'edit_request'), false); // untouched keys keep the viewer default

  const restrictedAdmin = { role: 'admin', permissions: { edit_request: false } };
  assert.equal(hasPermission(restrictedAdmin, 'edit_request'), false);
  assert.equal(hasPermission(restrictedAdmin, 'create_request'), true); // untouched keys keep the admin default
});

test('manage_users is never independently grantable, even if someone tries to set it', () => {
  const user = { role: 'admin', permissions: { manage_users: true } };
  assert.equal(hasPermission(user, 'manage_users'), false);
  assert.ok(!GRANTABLE_PERMISSION_KEYS.includes('manage_users'));
});

test('sanitizePermissions drops manage_users and any unknown key, keeps valid ones', () => {
  const out = sanitizePermissions({ manage_users: true, create_request: true, made_up_key: true, delete_records: false });
  assert.deepEqual(out, { create_request: true, delete_records: false });
});

test('sanitizePermissions coerces truthy/falsy values to real booleans', () => {
  const out = sanitizePermissions({ create_request: 1, edit_request: 0, register_po: 'yes' });
  assert.equal(out.create_request, true);
  assert.equal(out.edit_request, false);
  assert.equal(out.register_po, true);
});

test('sanitizePermissions handles missing/malformed input gracefully', () => {
  assert.deepEqual(sanitizePermissions(undefined), {});
  assert.deepEqual(sanitizePermissions(null), {});
  assert.deepEqual(sanitizePermissions('not an object'), {});
});

test('getEffectivePermissions always returns every grantable key, never leaves one undefined', () => {
  const perms = getEffectivePermissions({ role: 'admin', permissions: { create_request: true } });
  for (const key of GRANTABLE_PERMISSION_KEYS) {
    assert.equal(typeof perms[key], 'boolean', `expected ${key} to resolve to a boolean`);
  }
});

test('an unknown/missing role falls back to viewer-level (nothing granted) defaults', () => {
  assert.equal(hasPermission({}, 'create_request'), false);
  assert.equal(hasPermission({ role: 'some_future_role' }, 'create_request'), false);
});
