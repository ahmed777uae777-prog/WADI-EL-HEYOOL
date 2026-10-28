# منصة المعلّم الذكية

Cloudflare Worker يقدّم الصفحة (`public/index.html`) كملف ثابت، ويقدّم `/api/doc` لتخزين البيانات في قاعدة D1 (`school-db`).

- `src/worker.js` — نقطة الدخول: حماية بكلمة مرور + توجيه الطلبات.
- `functions/api/doc.js` — منطق القراءة/الكتابة في D1.
- `schema.sql` — جدول `docs`.

## النشر
مربوط بـ Cloudflare Workers Builds: أي `push` إلى `main` يُنشر تلقائيًا (`npx wrangler deploy`).

## الحماية (اختيارية حاليًا — الموقع مفتوح مؤقتًا)
⚠️ بدون كلمة مرور يستطيع أي شخص معه الرابط قراءة البيانات وتعديلها. لا تستورد بيانات طلاب حقيقية في هذا الوضع.
لتفعيل الحماية بكلمة مرور (HTTP Basic Auth):
Workers & Pages ← wadi-el-heyool ← Settings ← Variables and Secrets ← Add ← Type: **Secret**، الاسم `SITE_PASSWORD`.
عند الدخول: اسم المستخدم أي شيء، وكلمة المرور هي `SITE_PASSWORD`.

## استيراد البيانات الحالية
ملف `seed/seed.sql` خارج Git عمدًا (أسماء وأرقام طلاب). يُستورد من Console قاعدة `school-db` أو:
`npx wrangler d1 execute school-db --remote --file=seed/seed.sql`
