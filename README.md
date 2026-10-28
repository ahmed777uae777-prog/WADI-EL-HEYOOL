# منصة المعلّم الذكية

صفحة واحدة (`public/index.html`) + دالة Cloudflare Pages (`functions/api/doc.js`) تخزّن البيانات في قاعدة D1.

## النشر على Cloudflare Pages
1. أنشئ قاعدة البيانات: `npx wrangler d1 create school-db` ثم ضع `database_id` الناتج في `wrangler.toml`.
2. أنشئ الجدول: `npx wrangler d1 execute school-db --remote --file=schema.sql`
3. (اختياري) استورد البيانات الحالية: `npx wrangler d1 execute school-db --remote --file=seed/seed.sql` — الملف خارج Git عمدًا لأنه يحوي أسماء وأرقام طلاب.
4. اربط المستودع من لوحة Cloudflare: Workers & Pages ← Create ← Pages ← Connect to Git. Build command فارغ، Build output directory = `public`.
5. من إعدادات المشروع ← Settings ← Bindings أضف D1 باسم `DB` يشير إلى `school-db`.
6. **مهم:** فعّل Cloudflare Access على النطاق (Zero Trust ← Access ← Applications) وإلا فبيانات الطلاب متاحة لأي شخص يعرف الرابط.

ميزة الذكاء الاصطناعي (`sample`) تعمل داخل claude.ai فقط ولا تتوفر على Cloudflare.
