# MGE Security System

منظومة فحص أصالة المنتجات باستخدام NFC وQR والتحقق الخادمي.

## التشغيل

```bash
npm install
npm start
```

ثم افتح `http://localhost:3000/`. الصفحات الإضافية هي:

- `/writer.html` لمحطة البرمجة.
- `/print.html` لتوليد ملصقات QR.
- `/docs.html` للتوثيق الفني.
- `/security-showcase.html` لصفحة العرض.

يُفضّل ضبط `MGE_MASTER_KEY` في ملف `.env` قبل استخدام التحقق العتادي. مفتاح القيمة الافتراضية مخصص للتجربة فقط.