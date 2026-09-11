const test = require('node:test');
const assert = require('node:assert/strict');
const { fmtAuditValue, diffItems, describeFieldChanges, buildEditDetails } = require('../lib/auditDiff');

test('fmtAuditValue: empty/undefined/null all render as "(فاضي)"', () => {
  assert.equal(fmtAuditValue(''), '(فاضي)');
  assert.equal(fmtAuditValue(undefined), '(فاضي)');
  assert.equal(fmtAuditValue(null), '(فاضي)');
});

test('fmtAuditValue: numbers use en-US grouping (matches fmtMoney on the client)', () => {
  assert.equal(fmtAuditValue(1500), '1,500');
  assert.equal(fmtAuditValue(0), '0');
});

test('fmtAuditValue: long text gets truncated with an ellipsis', () => {
  const long = 'a'.repeat(100);
  const out = fmtAuditValue(long);
  assert.ok(out.length < long.length);
  assert.ok(out.endsWith('…'));
});

test('describeFieldChanges: a real change produces one "من X إلى Y" line', () => {
  const before = { customer: 'أحمد' };
  const patch = { customer: 'محمد' };
  const lines = describeFieldChanges(before, patch);
  assert.equal(lines.length, 1);
  assert.match(lines[0], /اسم العميل/);
  assert.match(lines[0], /أحمد/);
  assert.match(lines[0], /محمد/);
});

test('describeFieldChanges: a no-op patch (same value) produces nothing — this is the important guard', () => {
  const before = { customer: 'أحمد', quoteValue: 100 };
  const patch = { customer: 'أحمد', quoteValue: 100 };
  assert.deepEqual(describeFieldChanges(before, patch), []);
});

test('describeFieldChanges: untracked fields (stage, quoteStatus) are ignored on purpose', () => {
  const before = { stage: 'request', quoteStatus: 'pending' };
  const patch = { stage: 'followup', quoteStatus: 'po' };
  assert.deepEqual(describeFieldChanges(before, patch), []);
});

test('describeFieldChanges: only keys present in the patch are considered, even if before/after differ elsewhere', () => {
  const before = { customer: 'أحمد', phone: '0100' };
  const patch = { customer: 'أحمد' }; // phone not part of this patch at all
  assert.deepEqual(describeFieldChanges(before, patch), []);
});

test('describeFieldChanges: multiple changed fields each get their own line', () => {
  const before = { customer: 'أحمد', quoteValue: 1000 };
  const patch = { customer: 'محمد', quoteValue: 1200 };
  const lines = describeFieldChanges(before, patch);
  assert.equal(lines.length, 2);
});

test('diffItems: a changed unit price on an existing item', () => {
  const before = [{ item: 'لمبة LED', unitPrice: 100, quantity: 2, total: 200 }];
  const after = [{ item: 'لمبة LED', unitPrice: 150, quantity: 2, total: 300 }];
  const lines = diffItems(before, after);
  assert.equal(lines.length, 2); // unitPrice AND total both changed
  assert.ok(lines.some(l => l.includes('سعر الوحدة') && l.includes('100') && l.includes('150')));
  assert.ok(lines.some(l => l.includes('إجمالي البند') && l.includes('200') && l.includes('300')));
});

test('diffItems: an unchanged item produces no lines', () => {
  const items = [{ item: 'لمبة LED', unitPrice: 100, quantity: 2, total: 200 }];
  assert.deepEqual(diffItems(items, items.map(i => ({ ...i }))), []);
});

test('diffItems: an added item is reported', () => {
  const before = [{ item: 'لمبة LED', unitPrice: 100 }];
  const after = [{ item: 'لمبة LED', unitPrice: 100 }, { item: 'كابل', unitPrice: 50 }];
  const lines = diffItems(before, after);
  assert.equal(lines.length, 1);
  assert.match(lines[0], /تمت إضافة بند جديد/);
  assert.match(lines[0], /كابل/);
});

test('diffItems: a removed item is reported', () => {
  const before = [{ item: 'لمبة LED', unitPrice: 100 }, { item: 'كابل', unitPrice: 50 }];
  const after = [{ item: 'لمبة LED', unitPrice: 100 }];
  const lines = diffItems(before, after);
  assert.equal(lines.length, 1);
  assert.match(lines[0], /تم حذف البند/);
  assert.match(lines[0], /كابل/);
});

test('buildEditDetails: leads with the customer name, then the change lines, newline-separated', () => {
  const before = { customer: 'أحمد', quoteValue: 1000 };
  const patch = { quoteValue: 1200 };
  const details = buildEditDetails('أحمد', before, patch);
  const lines = details.split('\n');
  assert.equal(lines[0], 'العميل: أحمد');
  assert.equal(lines.length, 2);
});

test('buildEditDetails: still returns just the customer line when nothing tracked changed', () => {
  const before = { stage: 'request' };
  const patch = { stage: 'followup' }; // stage is untracked on purpose
  assert.equal(buildEditDetails('أحمد', before, patch), 'العميل: أحمد');
});
