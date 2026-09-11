const test = require('node:test');
const assert = require('node:assert/strict');
const { computeAlerts, ALERT_DUE_LOOKAHEAD_DAYS, ALERT_STALE_DAYS } = require('../public/js/alertUtils');

const TODAY = '2026-09-06'; // fixed reference date so tests never depend on when they run

function baseRecord(overrides) {
  return Object.assign({
    code: 'R1', stage: 'request', quoteStatus: 'pending', dateCreated: TODAY
  }, overrides);
}

test('thresholds are the values that were asked for', () => {
  assert.equal(ALERT_DUE_LOOKAHEAD_DAYS, 3);
  assert.equal(ALERT_STALE_DAYS, 7);
});

test('a closed record never appears in any alert bucket', () => {
  const records = [baseRecord({ stage: 'closed', dateCreated: '2026-08-01' })];
  const a = computeAlerts(records, TODAY);
  assert.equal(a.staleRequests.length, 0);
});

test('a record whose deal is already decided (quoteStatus !== pending) is excluded', () => {
  const records = [baseRecord({ stage: 'quote', quoteStatus: 'po', quoteDate: '2026-08-01' })];
  const a = computeAlerts(records, TODAY);
  assert.equal(a.staleQuotes.length, 0);
});

test('fixed-date request due in exactly 3 days shows up (boundary, inclusive)', () => {
  const records = [baseRecord({ orderType: 'طلب يوم محدد', requiredDate: '2026-09-09' })];
  const a = computeAlerts(records, TODAY);
  assert.equal(a.dueFixedDate.length, 1);
  assert.equal(a.dueFixedDate[0].daysLeft, 3);
});

test('fixed-date request due in 4 days does NOT show up yet (just past the boundary)', () => {
  const records = [baseRecord({ orderType: 'طلب يوم محدد', requiredDate: '2026-09-10' })];
  const a = computeAlerts(records, TODAY);
  assert.equal(a.dueFixedDate.length, 0);
});

test('an overdue tender (deadline already passed) keeps showing, as a negative daysLeft', () => {
  const records = [baseRecord({ orderType: 'مناقصة', requiredDate: '2026-08-20' })];
  const a = computeAlerts(records, TODAY);
  assert.equal(a.dueTender.length, 1);
  assert.equal(a.dueTender[0].daysLeft, -17);
});

test('due-date alerts are sorted most-urgent (most overdue) first', () => {
  const records = [
    baseRecord({ code: 'R1', orderType: 'مناقصة', requiredDate: '2026-09-08' }), // 2 days left
    baseRecord({ code: 'R2', orderType: 'مناقصة', requiredDate: '2026-09-01' })  // 5 days overdue
  ];
  const a = computeAlerts(records, TODAY);
  assert.equal(a.dueTender[0].r.code, 'R2');
  assert.equal(a.dueTender[1].r.code, 'R1');
});

test('a plain (non-tender, non-fixed-date) request with a requiredDate never triggers a due-date alert', () => {
  const records = [baseRecord({ orderType: 'طلب سعر عادي', requiredDate: '2026-09-06' })];
  const a = computeAlerts(records, TODAY);
  assert.equal(a.dueFixedDate.length, 0);
  assert.equal(a.dueTender.length, 0);
});

test('request stuck at exactly 7 days shows up (boundary, inclusive)', () => {
  const records = [baseRecord({ stage: 'request', dateCreated: '2026-08-30' })];
  const a = computeAlerts(records, TODAY);
  assert.equal(a.staleRequests.length, 1);
  assert.equal(a.staleRequests[0].days, 7);
});

test('request stuck at 6 days does NOT show up yet', () => {
  const records = [baseRecord({ stage: 'request', dateCreated: '2026-08-31' })];
  const a = computeAlerts(records, TODAY);
  assert.equal(a.staleRequests.length, 0);
});

test('a request in "request" stage never counts as a stale followup, and vice versa', () => {
  const records = [
    baseRecord({ code: 'R1', stage: 'request', dateCreated: '2026-08-20' }),
    baseRecord({ code: 'R2', stage: 'followup', dateCreated: '2026-08-20' })
  ];
  const a = computeAlerts(records, TODAY);
  assert.equal(a.staleRequests.length, 1);
  assert.equal(a.staleRequests[0].r.code, 'R1');
  assert.equal(a.staleFollowups.length, 1);
  assert.equal(a.staleFollowups[0].r.code, 'R2');
});

test('stale quote uses quoteDate when present, falling back to dateCreated otherwise', () => {
  const withQuoteDate = baseRecord({ code: 'R1', stage: 'quote', dateCreated: '2026-09-01', quoteDate: '2026-08-25' });
  const withoutQuoteDate = baseRecord({ code: 'R2', stage: 'quote', dateCreated: '2026-08-25' });
  const a = computeAlerts([withQuoteDate, withoutQuoteDate], TODAY);
  assert.equal(a.staleQuotes.length, 2);
  const r1 = a.staleQuotes.find(x => x.r.code === 'R1');
  const r2 = a.staleQuotes.find(x => x.r.code === 'R2');
  assert.equal(r1.days, 12); // from quoteDate (Aug 25), not dateCreated (Sep 1)
  assert.equal(r2.days, 12); // from dateCreated, since quoteDate is missing
});

test('stale-item lists are sorted most-stuck (most days) first', () => {
  const records = [
    baseRecord({ code: 'R1', stage: 'request', dateCreated: '2026-08-30' }), // 7 days
    baseRecord({ code: 'R2', stage: 'request', dateCreated: '2026-08-20' })  // 17 days
  ];
  const a = computeAlerts(records, TODAY);
  assert.equal(a.staleRequests[0].r.code, 'R2');
  assert.equal(a.staleRequests[1].r.code, 'R1');
});

test('an empty records array produces empty (not missing) buckets', () => {
  const a = computeAlerts([], TODAY);
  assert.deepEqual(a, { dueFixedDate: [], dueTender: [], staleRequests: [], staleFollowups: [], staleQuotes: [] });
});
