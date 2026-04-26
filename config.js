// ════════════════════════════════════════════════
// config.js — ATLAS إعدادات الواجهة الأمامية
// ملاحظة: PayPal Client ID يُجلب من السيرفر بأمان
// ════════════════════════════════════════════════

const ATLAS_CONFIG = {
  // عنوان السيرفر — يتعرف تلقائياً
  BACKEND_URL: (typeof window !== 'undefined') ? window.location.origin : 'http://localhost:3000'
  // ملاحظة: PROFIT_MARGIN أُزيل — الأسعار تُحسب من قاعدة البيانات فقط (server.js)
};

if (typeof window !== 'undefined') {
  window.ATLAS_CONFIG = ATLAS_CONFIG;
}
