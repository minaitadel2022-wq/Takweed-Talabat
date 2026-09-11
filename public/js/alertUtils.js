// ================= Shared alerts-computation logic =================
// Used by BOTH the browser (public/index.html, via window.AlertUtils) and
// the test suite (test/alertUtils.test.js, via require) — same reasoning as
// public/js/dateUtils.js: one copy instead of logic that only ever lived in
// the browser and was never exercised by anything else.
//
// "Five kinds of needs-attention items", all computed from a plain records
// array. Everything here is scoped to records that are still an open/active
// pipeline item: not closed, and not yet resolved to PO/اعتذار/خسارة
// (quoteStatus stays 'pending' the whole time a record is sitting in
// "طلبات الأسعار"/"متابعة", so this one check works for all five).
(function (root, factory) {
  if (typeof module === 'object' && module.exports) {
    module.exports = factory(require('./dateUtils')); // Node (tests)
  } else {
    root.AlertUtils = factory(root.DateUtils); // browser <script> tag
  }
}(typeof self !== 'undefined' ? self : this, function (DateUtils) {
  const { daysBetweenISO, todayLocalISO } = DateUtils;

  // Thresholds are named constants (not scattered magic numbers) so they're
  // easy to tune later without hunting through the computation code.
  const ALERT_DUE_LOOKAHEAD_DAYS = 3; // start warning this many days before a tender/fixed-date deadline
  const ALERT_STALE_DAYS = 7;         // "a week with no progress"

  // `today` defaults to the real current date but can be overridden — this
  // is what lets tests assert exact day-boundary behavior (e.g. "exactly 7
  // days ago" vs "6 days ago") without depending on when the test happens
  // to run.
  function computeAlerts(records, today) {
    today = today || todayLocalISO();
    // Still-open pipeline items: not closed, outcome not yet decided.
    const open = records.filter(r => r.stage !== 'closed' && r.quoteStatus === 'pending');

    function dueList(orderType) {
      return open
        .filter(r => r.orderType === orderType && r.requiredDate)
        .map(r => ({ r, daysLeft: daysBetweenISO(today, r.requiredDate) }))
        .filter(x => x.daysLeft <= ALERT_DUE_LOOKAHEAD_DAYS)
        .sort((a, b) => a.daysLeft - b.daysLeft);
    }
    function staleList(stage, dateField) {
      return open
        .filter(r => r.stage === stage)
        .map(r => ({ r, days: daysBetweenISO(r[dateField] || r.dateCreated, today) }))
        .filter(x => x.days >= ALERT_STALE_DAYS)
        .sort((a, b) => b.days - a.days);
    }
    return {
      dueFixedDate: dueList('طلب يوم محدد'),
      dueTender: dueList('مناقصة'),
      staleRequests: staleList('request', 'dateCreated'),
      staleFollowups: staleList('followup', 'dateCreated'),
      staleQuotes: staleList('quote', 'quoteDate')
    };
  }

  return { computeAlerts, ALERT_DUE_LOOKAHEAD_DAYS, ALERT_STALE_DAYS };
}));
