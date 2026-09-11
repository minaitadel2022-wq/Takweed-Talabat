// ================= Shared date-math helpers =================
// Used by BOTH the browser (loaded via <script src="js/dateUtils.js"> in
// public/index.html) and the server (required directly from server.js).
// Having exactly ONE copy is what prevents client/server date-logic drift —
// which is exactly what caused an earlier bug: building "the 1st of this
// month" with `new Date(y, m, 1).toISOString()` converts to UTC first, and
// for anyone east of UTC (e.g. Cairo, UTC+2/+3) that rolls the date back to
// the last day of the PREVIOUS month. It silently dropped the current month
// from period calculations and the trend chart in two separate places
// (index.html and server.js) that had each hand-rolled the same logic.
//
// See test/dateUtils.test.js for the regression test that pins this down —
// if this file is ever "simplified" back to using toISOString(), that test
// will fail immediately instead of the bug quietly coming back.
(function (root, factory) {
  if (typeof module === 'object' && module.exports) {
    module.exports = factory(); // Node (server.js, tests)
  } else {
    root.DateUtils = factory(); // browser <script> tag
  }
}(typeof self !== 'undefined' ? self : this, function () {
  // Formats a Date using its LOCAL calendar fields (getFullYear/getMonth/
  // getDate), never toISOString() — see the file header for why that matters.
  function localISODate(d) {
    const pad = n => String(n).padStart(2, '0');
    return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`;
  }
  function localISOMonth(d) {
    const pad = n => String(n).padStart(2, '0');
    return `${d.getFullYear()}-${pad(d.getMonth() + 1)}`;
  }
  // Whole days between two "YYYY-MM-DD" strings, built from LOCAL date parts.
  // Deliberately not `new Date(isoString)` — a bare "YYYY-MM-DD" is parsed as
  // UTC midnight by the JS spec, which is a *different* pitfall from the one
  // above but bites the same way for anyone east of UTC.
  function daysBetweenISO(fromISO, toISO) {
    const [fy, fm, fd] = fromISO.split('-').map(Number);
    const [ty, tm, td] = toISO.split('-').map(Number);
    return Math.round((new Date(ty, tm - 1, td) - new Date(fy, fm - 1, fd)) / 86400000);
  }
  function todayLocalISO() {
    return localISODate(new Date());
  }
  // Arabic day-count phrasing used in the alerts UI.
  function daysWordAr(n) {
    return n === 1 ? 'يوم واحد' : n === 2 ? 'يومين' : `${n} يوم`;
  }
  return { localISODate, localISOMonth, daysBetweenISO, todayLocalISO, daysWordAr };
}));
