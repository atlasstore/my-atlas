// ════════════════════════════════════════════════
// security.js — ATLAS Frontend Security & Sanitization
// ════════════════════════════════════════════════
// ⚠️  هذا الملف للواجهة الأمامية (Frontend) فقط.
//     الـ Backend يملك sanitize() الخاصة به في server.js
//     يجب أن تتطابق الحدود (max lengths) بين الملفين.
// ════════════════════════════════════════════════

const AtlasSecurity = {

  // منع هجمات XSS — الحد 1000 حرف ليتطابق مع server.js str()
  sanitize: function(str, max) {
    if (!str) return '';
    max = (typeof max === 'number' && max > 0) ? max : 1000;
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;')
      // منع javascript: و data: في الروابط
      .replace(/javascript\s*:/gi, '')
      .replace(/data\s*:/gi, '')
      .slice(0, max);
  },

  // التحقق من صحة الإيميل
  isValidEmail: function(email) {
    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(email || ''));
  },

  // تنظيف نص عادي للعرض في DOM (textContent آمن — لكن هذا للنصوص المحوّلة لـ HTML)
  escHtml: function(str) {
    var d = document.createElement('div');
    d.textContent = String(str || '');
    return d.innerHTML;
  }

};

if (typeof window !== 'undefined') {
  window.AtlasSecurity = AtlasSecurity;
}
