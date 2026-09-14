const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const crypto = require('crypto');
const { AesCmac } = require('aes-cmac');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;
const databasePath = process.env.MGE_DB_PATH || './mge_security.db';
const masterKeyHex = process.env.MGE_MASTER_KEY || '00112233445566778899AABBCCDDEEFF';
const MASTER_KEY = Buffer.from(masterKeyHex, 'hex');

if (MASTER_KEY.length !== 16) {
    throw new Error('MGE_MASTER_KEY must be a 16-byte hexadecimal AES key');
}

app.use(express.static(path.join(__dirname, 'www')));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const db = new sqlite3.Database(databasePath);

db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS products (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        description TEXT,
        image_url TEXT NOT NULL
    )`);
    db.run(`CREATE TABLE IF NOT EXISTS nfc_tags (
        uid TEXT PRIMARY KEY,
        product_id INTEGER NOT NULL,
        batch_number TEXT NOT NULL,
        production_date TEXT NOT NULL,
        last_counter INTEGER DEFAULT 0,
        scan_count INTEGER DEFAULT 0,
        is_active INTEGER DEFAULT 1,
        FOREIGN KEY (product_id) REFERENCES products (id)
    )`);
    db.run(`INSERT OR IGNORE INTO products (id, name, description, image_url)
            VALUES (1, 'سيروم علاجي للشعر - دكتور ريليف',
                    'تركيبة طبيعية مركزة لإعادة بناء بصيلات الشعر التالفة.',
                    'https://images.unsplash.com/photo-1608248597358-1f19b5962e24?w=500')`);
    db.run(`INSERT OR IGNORE INTO nfc_tags
            (uid, product_id, batch_number, production_date, last_counter, scan_count)
            VALUES ('04A28F1B3E6C80', 1, 'BATCH-2026-X', '2026-09-01', 0, 0)`);
});

function decryptPiccData(piccHex, key) {
    if (!/^[\da-fA-F]+$/.test(piccHex) || piccHex.length === 0 || piccHex.length % 32 !== 0) {
        throw new Error('Invalid PICC data');
    }
    const decipher = crypto.createDecipheriv('aes-128-cbc', key, Buffer.alloc(16));
    decipher.setAutoPadding(false);
    const decrypted = Buffer.concat([decipher.update(Buffer.from(piccHex, 'hex')), decipher.final()]);
    if (decrypted.length < 11) throw new Error('Incomplete PICC data');
    return {
        uid: decrypted.subarray(1, 8).toString('hex').toUpperCase(),
        counter: decrypted.readUIntLE(8, 3)
    };
}

function deriveSessionKey(masterKey, counter, uidBuffer) {
    const sessionVector = Buffer.concat([
        Buffer.from([0x3C, 0xC3, 0x00, 0x01, 0x00, 0x80]),
        uidBuffer,
        Buffer.from([counter & 0xFF, (counter >> 8) & 0xFF, (counter >> 16) & 0xFF])
    ]);
    const cipher = crypto.createCipheriv('aes-128-cbc', masterKey, Buffer.alloc(16));
    cipher.setAutoPadding(false);
    return Buffer.concat([cipher.update(sessionVector), cipher.final()]).subarray(0, 16);
}

function productQuery() {
    return `SELECT t.*, p.name, p.description, p.image_url
            FROM nfc_tags t JOIN products p ON t.product_id = p.id WHERE t.uid = ?`;
}

function sendProductResult(row, scanCount, res) {
    res.json({
        status: 'original',
        message: 'منتج أصلي وموثق رسمياً (MGE Verified)',
        data: {
            uid: row.uid,
            name: row.name,
            description: row.description,
            imageUrl: row.image_url,
            batch: row.batch_number,
            productionDate: row.production_date,
            scanCount
        }
    });
}

function handleManualCheck(code, res) {
    db.get(productQuery(), [code.trim()], (err, row) => {
        if (err) return res.status(500).json({ status: 'error', message: 'تعذر الوصول إلى قاعدة البيانات.' });
        if (!row || !row.is_active) return res.status(404).json({ status: 'fake', message: 'الكود غير مسجل أو منتهي الصلاحية.' });
        const newCount = row.scan_count + 1;
        db.run('UPDATE nfc_tags SET scan_count = ? WHERE uid = ?', [newCount, row.uid], (updateError) => {
            if (updateError) return res.status(500).json({ status: 'error', message: 'تعذر تسجيل عملية الفحص.' });
            sendProductResult(row, newCount, res);
        });
    });
}

app.get('/verify', async (req, res) => {
    const { picc_data: piccData, cmac, c } = req.query;
    if (c && !piccData) return handleManualCheck(c, res);
    if (!piccData || !cmac) return res.status(400).send('بيانات فحص الشريحة غير صالحة أو تم التلاعب بالرابط!');

    try {
        const { uid, counter } = decryptPiccData(piccData, MASTER_KEY);
        const sessionMacKey = deriveSessionKey(MASTER_KEY, counter, Buffer.from(uid, 'hex'));
        const fullCmac = await new AesCmac(sessionMacKey).calculate(Buffer.alloc(0));
        const computedCmac = fullCmac.subarray(1, 9).toString('hex').toUpperCase();
        if (computedCmac !== String(cmac).toUpperCase()) {
            return res.status(403).send('تحذير أمني: الشريحة مقلدة أو تم نسخ الرابط بشكل غير قانوني!');
        }

        db.get(productQuery(), [uid], (err, row) => {
            if (err) return res.status(500).send('تعذر الوصول إلى قاعدة البيانات.');
            if (!row) return res.status(404).send('هذا المعرف العتادي غير مسجل في قواعد بيانات المصنع.');
            if (!row.is_active) return res.status(403).send('تم إيقاف صلاحية هذه القطعة من قبل إدارة الجودة.');
            if (counter <= row.last_counter && row.last_counter !== 0) {
                return res.status(409).send('تحذير أمني: تم رصد محاولة استخدام رابط تم فتحه مسبقاً (رابط منسوخ)!');
            }
            const newScanCount = row.scan_count + 1;
            db.run('UPDATE nfc_tags SET last_counter = ?, scan_count = ? WHERE uid = ?', [counter, newScanCount, uid], (updateError) => {
                if (updateError) return res.status(500).send('تعذر تسجيل عملية الفحص.');
                sendProductResult(row, newScanCount, res);
            });
        });
    } catch (error) {
        console.error('Auth Error:', error.message);
        res.status(400).send('فشل في فك شفرة البيانات الأمنية للعبوة.');
    }
});

app.get('/health', (_req, res) => res.json({ status: 'ok' }));

if (require.main === module) {
    app.listen(PORT, () => console.log(`MGE Server running on port ${PORT}`));
}

module.exports = app;
