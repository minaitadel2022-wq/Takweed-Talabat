// Run with: npm test   (or: node --test test/)
//
// This file pins down the exact bug that started all of this: building "the
// 1st of the month" with new Date(y, m, 1) and then formatting it with
// toISOString() silently rolls the date back a day for anyone east of UTC
// (Cairo is UTC+2/+3). The fix (localISODate/localISOMonth in
// public/js/dateUtils.js) reads the LOCAL calendar fields directly instead.
//
// We force the timezone to Africa/Cairo here specifically so this test keeps
// catching the bug regardless of what timezone the machine running the test
// suite happens to be in (a UTC CI server would never have noticed the
// original bug at all).
process.env.TZ = 'Africa/Cairo';

const test = require('node:test');
const assert = require('node:assert/strict');
const { localISODate, localISOMonth, daysBetweenISO, todayLocalISO, daysWordAr } = require('../public/js/dateUtils');

test('localISODate: the original bug — 1st of the month must stay the 1st', () => {
  const firstOfSeptember = new Date(2026, 8, 1); // month is 0-indexed: 8 = September
  assert.equal(localISODate(firstOfSeptember), '2026-09-01');

  // Show explicitly what the OLD (buggy) code did, so this test fails loudly
  // if anyone "simplifies" dateUtils.js back to using toISOString().
  const buggyOldWay = firstOfSeptember.toISOString().slice(0, 10);
  assert.equal(buggyOldWay, '2026-08-31', 'sanity check: this documents WHY the bug happened, not a requirement');
  assert.notEqual(localISODate(firstOfSeptember), buggyOldWay);
});

test('localISODate: last day of a 31-day month (end-of-month boundary)', () => {
  const lastOfSeptember = new Date(2026, 8, 30);
  assert.equal(localISODate(lastOfSeptember), '2026-09-30');
});

test('localISODate: pads single-digit month and day', () => {
  assert.equal(localISODate(new Date(2026, 0, 5)), '2026-01-05');
});

test('localISODate: December 31st does not roll into next year', () => {
  assert.equal(localISODate(new Date(2026, 11, 31)), '2026-12-31');
});

test('localISOMonth: the same bug, one level up — 1st of the month must stay in the right MONTH', () => {
  const firstOfSeptember = new Date(2026, 8, 1);
  assert.equal(localISOMonth(firstOfSeptember), '2026-09');
  // the old toISOString() approach would have said "2026-08" instead
  assert.notEqual(localISOMonth(firstOfSeptember), firstOfSeptember.toISOString().slice(0, 7));
});

test('localISOMonth: pads single-digit month', () => {
  assert.equal(localISOMonth(new Date(2026, 0, 15)), '2026-01');
});

test('daysBetweenISO: whole days between two dates in the same month', () => {
  assert.equal(daysBetweenISO('2026-09-01', '2026-09-08'), 7);
});

test('daysBetweenISO: crossing a month boundary', () => {
  assert.equal(daysBetweenISO('2026-08-28', '2026-09-02'), 5);
});

test('daysBetweenISO: crossing a year boundary', () => {
  assert.equal(daysBetweenISO('2026-12-30', '2027-01-02'), 3);
});

test('daysBetweenISO: negative when "to" is before "from" (used for overdue deadlines)', () => {
  assert.equal(daysBetweenISO('2026-09-06', '2026-09-01'), -5);
});

test('daysBetweenISO: same day is zero', () => {
  assert.equal(daysBetweenISO('2026-09-06', '2026-09-06'), 0);
});

test('todayLocalISO: matches localISODate(new Date()) — no drift between the two', () => {
  assert.equal(todayLocalISO(), localISODate(new Date()));
});

test('daysWordAr: singular, dual, and plural Arabic phrasing', () => {
  assert.equal(daysWordAr(1), 'يوم واحد');
  assert.equal(daysWordAr(2), 'يومين');
  assert.equal(daysWordAr(5), '5 يوم');
});
