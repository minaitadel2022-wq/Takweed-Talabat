// ================= Field-level change tracking =================
// The activity log used to only say "تعديل بيانات" (an edit happened) —
// enough to know something changed, not what. This turns every edit's log
// entry into a field-by-field "X: من كذا إلى كذا" list (see describeFieldChanges,
// used from the PATCH /api/records/:id handler in server.js), so a dispute
// over a price or a date has an actual paper trail instead of relying on
// someone's memory.
//
// Pulled out into its own module (instead of living inline in server.js) so
// it can be unit-tested directly — see test/auditDiff.test.js — without
// having to spin up the whole Express app.
//
// Only fields worth auditing this way are listed here — 'stage' and
// 'quoteStatus' are deliberately left out because the PATCH handler already
// writes a clear Arabic sentence for those transitions (e.g. "تحويل العرض
// إلى أمر شراء (PO)"); listing them here too would just repeat the same
// information in a second, more awkward form.
const AUDITED_FIELDS = {
  customer: 'اسم العميل', company: 'اسم الشركة', phone: 'التليفون', email: 'الإيميل',
  orderType: 'نوع الطلب', requiredDate: 'الموعد النهائي',
  salesEngineer: 'مهندس المبيعات', techOfficeEngineer: 'مهندس المكتب الفني',
  quoteValue: 'قيمة العرض', quoteValidity: 'صلاحية العرض', quoteNotes: 'ملاحظات العرض',
  followupStatus: 'حالة المتابعة', followupNotes: 'ملاحظات المتابعة',
  codeArrivalDate: 'تاريخ وصول الكود من المكتب الفني',
  declineReason: 'سبب الاعتذار', lossReason: 'سبب الخسارة', closeReason: 'سبب الإغلاق'
};

function fmtAuditValue(v) {
  if (v === undefined || v === null || v === '') return '(فاضي)';
  // en-US here matches fmtMoney() on the client (plain "1,500" digits) —
  // not ar-EG, which would print Arabic-Indic numerals inconsistent with
  // every other number shown in the app.
  if (typeof v === 'number') return v.toLocaleString('en-US');
  const s = String(v);
  return s.length > 70 ? s.slice(0, 70) + '…' : s;
}

// Compares the "بنود" arrays by position and describes what actually changed
// per row — added/removed items, or a changed name/price/quantity/brand —
// instead of a vague "تم تعديل البنود".
function diffItems(beforeItems, afterItems) {
  const lines = [];
  const before = beforeItems || [];
  const after = afterItems || [];
  const max = Math.max(before.length, after.length);
  for (let i = 0; i < max; i++) {
    const b = before[i], a = after[i];
    if (b && !a) { lines.push(`تم حذف البند: ${b.item}`); continue; }
    if (!b && a) { lines.push(`تمت إضافة بند جديد: ${a.item}`); continue; }
    if (!b || !a) continue;
    const label = a.item || b.item || `بند ${i + 1}`;
    const fieldChecks = [
      ['item', 'اسم البند'], ['brand', 'الماركة'], ['description', 'الوصف'],
      ['quantity', 'الكمية'], ['unitPrice', 'سعر الوحدة'], ['total', 'إجمالي البند']
    ];
    for (const [key, fLabel] of fieldChecks) {
      if (String(b[key] ?? '') !== String(a[key] ?? '')) {
        lines.push(`${label} — ${fLabel}: من ${fmtAuditValue(b[key])} إلى ${fmtAuditValue(a[key])}`);
      }
    }
  }
  return lines;
}

// The main entry point: given the record BEFORE the patch and the patch
// itself, returns an array of "field: من X إلى Y" lines for everything that
// actually changed — used to build the activity-log "details" text.
function describeFieldChanges(before, patch) {
  const lines = [];
  for (const key of Object.keys(AUDITED_FIELDS)) {
    if (!(key in patch)) continue;
    const b = before[key], a = patch[key];
    if (String(b ?? '') === String(a ?? '')) continue;
    lines.push(`${AUDITED_FIELDS[key]}: من ${fmtAuditValue(b)} إلى ${fmtAuditValue(a)}`);
  }
  if ('items' in patch) lines.push(...diffItems(before.items, patch.items));
  return lines;
}

// Activity-log "details" text for a PATCH /api/records/:id call: the
// customer name for quick scanning, plus one line per field that actually
// changed (empty when the patch only touched an untracked field like stage,
// which the "action" text already narrates on its own).
function buildEditDetails(customer, before, patch) {
  const changeLines = describeFieldChanges(before, patch);
  return [`العميل: ${customer}`, ...changeLines].join('\n');
}

module.exports = { AUDITED_FIELDS, fmtAuditValue, diffItems, describeFieldChanges, buildEditDetails };
