// ================= Shared permission model =================
// Used by BOTH the browser (public/index.html, via window.Permissions) and
// the server (server.js, via require) — same "one copy" reasoning as
// dateUtils.js/alertUtils.js: the list of permission keys, their labels, and
// the logic for resolving a user's effective permissions must never drift
// between what the UI shows as checkboxes and what the server actually
// enforces, or a checkbox could show "off" while the server still allows the
// action (or vice versa).
//
// Design notes (see the chat that introduced this for the full reasoning):
// - role stays in the user record as a fast top-level switch: 'super_admin'
//   always has every permission, no matter what — enforced here, not
//   editable via checkboxes.
// - 'manage_users' is NOT independently grantable. Letting a non-super-admin
//   manage user accounts (including their own permissions) is a privilege-
//   escalation risk, not just a data-access one, so it stays tied to the
//   super_admin role only. It's still listed here (with grantable:false) so
//   the permissions page can show it for transparency instead of silently
//   omitting a real capability from the picture.
// - Every other permission is independently grantable to an 'admin' or
//   'viewer' role user, and once a user has an explicit `permissions` object
//   saved, that object is authoritative for them — it does NOT keep falling
//   back to role-based defaults field-by-field. DEFAULT_PERMISSIONS is only
//   used to pre-fill sensible starting values (e.g. for a brand-new user, or
//   one saved before this feature existed).
(function (root, factory) {
  if (typeof module === 'object' && module.exports) {
    module.exports = factory(); // Node (server.js, tests)
  } else {
    root.Permissions = factory(); // browser <script> tag
  }
}(typeof self !== 'undefined' ? self : this, function () {

  const PERMISSION_GROUPS = [
    {
      key: 'requests', label_ar: 'طلبات الأسعار', label_en: 'Price Requests',
      perms: [
        { key: 'create_request', label_ar: 'إنشاء طلب سعر جديد', label_en: 'Create a new price request' },
        { key: 'edit_request', label_ar: 'تعديل بيانات الطلب (العميل، النوع، الموعد، البنود...)', label_en: 'Edit request details (customer, type, deadline, items...)' },
        { key: 'move_to_followup', label_ar: 'ترحيل الطلب لمرحلة المتابعة', label_en: 'Move a request to follow-up' }
      ]
    },
    {
      key: 'followup', label_ar: 'المتابعة', label_en: 'Follow-up',
      perms: [
        { key: 'price_items', label_ar: 'تسعير بنود الطلب', label_en: 'Price line items' },
        { key: 'update_followup_status', label_ar: 'تغيير حالة/ملاحظات المتابعة وتاريخ وصول الكود', label_en: 'Update follow-up status/notes and code-arrival date' },
        { key: 'close_followup', label_ar: 'إغلاق طلب من المتابعة أو إرجاعه', label_en: 'Close a request from follow-up, or reopen it' },
        { key: 'convert_to_quote', label_ar: 'تحويل الطلب لعرض سعر', label_en: 'Convert a request to a quote' }
      ]
    },
    {
      key: 'quotes', label_ar: 'عروض الأسعار', label_en: 'Quotes',
      perms: [
        { key: 'register_po', label_ar: 'تسجيل أمر توريد (PO)', label_en: 'Register a purchase order (PO)' },
        { key: 'register_decline', label_ar: 'تسجيل اعتذار عن عرض', label_en: 'Register a decline' },
        { key: 'register_loss', label_ar: 'تسجيل خسارة عرض', label_en: 'Register a loss' },
        { key: 'revert_quote_status', label_ar: 'إعادة عرض سعر لقيد الانتظار', label_en: 'Revert a quote back to pending' },
        { key: 'manage_offer_docs', label_ar: 'رفع/توليد ملفات العرض المالي والفني وصور المنتج', label_en: 'Manage offer documents & product images' },
        { key: 'update_sent_to_customer', label_ar: 'تحديد إرسال العرض إلى العميل', label_en: 'Mark a quote as sent to the customer' },
        { key: 'update_quote_response', label_ar: 'تدوين رد العميل والإجراء المتخذ', label_en: 'Record the customer response & action taken' }
      ]
    },
    {
      key: 'general', label_ar: 'عام', label_en: 'General',
      perms: [
        { key: 'delete_records', label_ar: 'حذف طلبات نهائياً (خطير)', label_en: 'Permanently delete requests (dangerous)' },
        { key: 'view_customers', label_ar: 'الاطلاع على قائمة العملاء', label_en: 'View the customer list' },
        { key: 'view_activity_log', label_ar: 'الاطلاع على سجل الأنشطة', label_en: 'View the activity log' },
        { key: 'export_reports', label_ar: 'تصدير تقارير Excel', label_en: 'Export Excel reports' },
        { key: 'import_sp', label_ar: 'استيراد بيانات من ملف Excel', label_en: 'Import data from an Excel file' },
        { key: 'view_monthly_report', label_ar: 'الاطلاع على التقرير الشهري لمدير المبيعات', label_en: 'View the monthly sales-manager report' }
      ]
    },
    {
      key: 'admin', label_ar: 'الإدارة', label_en: 'Administration',
      perms: [
        // Not independently grantable — see the file header comment.
        { key: 'manage_users', label_ar: 'إدارة المستخدمين وصلاحياتهم', label_en: 'Manage users & permissions', grantable: false }
      ]
    }
  ];

  const ALL_PERMISSION_KEYS = [];
  const GRANTABLE_PERMISSION_KEYS = [];
  for (const group of PERMISSION_GROUPS) {
    for (const p of group.perms) {
      ALL_PERMISSION_KEYS.push(p.key);
      if (p.grantable !== false) GRANTABLE_PERMISSION_KEYS.push(p.key);
    }
  }

  // Starting defaults for a user who has no explicit `permissions` object yet
  // (a brand-new user, or one saved before this feature existed). Everything
  // an 'admin' can do day-to-day defaults to on; the two higher-risk ones
  // (delete_records, and manage_users which isn't grantable anyway) default
  // to off even for admins, and must be turned on explicitly.
  const DEFAULT_PERMISSIONS = { admin: {}, viewer: {} };
  for (const key of GRANTABLE_PERMISSION_KEYS) {
    DEFAULT_PERMISSIONS.admin[key] = (key !== 'delete_records');
    DEFAULT_PERMISSIONS.viewer[key] = false;
  }

  // Returns the full, resolved set of permissions for a user: super_admin
  // always gets everything; anyone else gets their own saved `permissions`
  // object merged over the role's defaults (so an old user record saved
  // before this feature existed still behaves the way it always did).
  function getEffectivePermissions(user) {
    const result = {};
    if (user && user.role === 'super_admin') {
      for (const key of ALL_PERMISSION_KEYS) result[key] = true;
      return result;
    }
    const base = DEFAULT_PERMISSIONS[(user && user.role) || 'viewer'] || DEFAULT_PERMISSIONS.viewer;
    for (const key of GRANTABLE_PERMISSION_KEYS) {
      const saved = user && user.permissions ? user.permissions[key] : undefined;
      result[key] = saved !== undefined ? !!saved : !!base[key];
    }
    result.manage_users = false; // never grantable outside super_admin
    return result;
  }

  function hasPermission(user, key) {
    return !!getEffectivePermissions(user)[key];
  }

  // Filters/coerces a raw permissions object (e.g. from a PATCH body) down to
  // only the keys that are actually grantable — anything else (unknown keys,
  // or attempts to set manage_users) is silently dropped rather than stored.
  function sanitizePermissions(raw) {
    const out = {};
    if (!raw || typeof raw !== 'object') return out;
    for (const key of GRANTABLE_PERMISSION_KEYS) {
      if (key in raw) out[key] = !!raw[key];
    }
    return out;
  }

  return {
    PERMISSION_GROUPS, ALL_PERMISSION_KEYS, GRANTABLE_PERMISSION_KEYS, DEFAULT_PERMISSIONS,
    getEffectivePermissions, hasPermission, sanitizePermissions
  };
}));
