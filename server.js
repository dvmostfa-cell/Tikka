require('dotenv').config();

const express = require('express');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');
const crypto = require('crypto');
const PDFDocument = require('pdfkit');
const { getStore } = require('@netlify/blobs');

const app = express();

const PORT = Number(process.env.PORT || 3000);
const ROOT = __dirname;

const isNetlify =
  !!process.env.NETLIFY ||
  !!process.env.NETLIFY_DEV ||
  !!process.env.AWS_LAMBDA_FUNCTION_NAME;

const SECRET =
  process.env.JWT_SECRET ||
  'tikka-dev-secret-change-me';

const corsOrigin = process.env.CORS_ORIGIN || '*';

/* =========================
   NETLIFY BLOBS
========================= */

const store = getStore({
  name: 'tikka-data'
});

const KEYS = {
  users: 'users',
  orders: 'orders',
  messages: 'messages'
};

async function read(key) {
  const data = await store.getJSON(KEYS[key]);

  if (!Array.isArray(data)) {
    return [];
  }

  return data;
}

async function write(key, data) {
  await store.setJSON(KEYS[key], data);
}

/* =========================
   HELPERS
========================= */

const id = prefix =>
  `${prefix}-${Date.now()}-${crypto.randomBytes(3).toString('hex')}`;

const token = user =>
  jwt.sign(
    {
      id: user.id,
      email: user.email,
      role: user.role,
      name: user.name
    },
    SECRET,
    {
      expiresIn: '7d'
    }
  );

function safeUser(user) {
  if (!user) return null;

  const { passwordHash, ...safe } = user;

  return safe;
}

/* =========================
   ADMIN INITIALIZATION
========================= */

async function ensureAdmin() {
  const users = await read('users');

  const adminEmail = String(
    process.env.ADMIN_EMAIL || 'admin@tikka.local'
  )
    .trim()
    .toLowerCase();

  if (users.some(user => user.email === adminEmail)) {
    return;
  }

  const password =
    process.env.ADMIN_PASSWORD || 'ChangeMe123!';

  const adminUser = {
    id: id('USR'),
    name: 'Tikka Admin',
    email: adminEmail,
    passwordHash: await bcrypt.hash(password, 12),
    role: 'admin',
    createdAt: new Date().toISOString()
  };

  users.push(adminUser);

  await write('users', users);

  console.log(`Admin created: ${adminEmail}`);
}

/* =========================
   MIDDLEWARE
========================= */

app.use(
  cors({
    origin: corsOrigin === '*' ? true : corsOrigin
  })
);

app.use(
  express.json({
    limit: '1mb'
  })
);

app.use(
  express.urlencoded({
    extended: true
  })
);

app.use(
  rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 300,
    standardHeaders: true,
    legacyHeaders: false
  })
);

app.use(
  express.static(
    path.join(ROOT, 'public')
  )
);

/* =========================
   AUTH
========================= */

async function auth(req, res, next) {
  const header =
    req.headers.authorization || '';

  if (!header.startsWith('Bearer ')) {
    return res.status(401).json({
      success: false,
      message: 'يجب تسجيل الدخول'
    });
  }

  try {
    req.user = jwt.verify(
      header.slice(7),
      SECRET
    );

    next();
  } catch {
    return res.status(401).json({
      success: false,
      message: 'جلسة الدخول غير صالحة أو منتهية'
    });
  }
}

function admin(req, res, next) {
  if (req.user?.role !== 'admin') {
    return res.status(403).json({
      success: false,
      message: 'صلاحيات المدير مطلوبة'
    });
  }

  next();
}

/* =========================
   HEALTH
========================= */

app.get('/api/health', (req, res) => {
  res.json({
    success: true,
    status: 'healthy',
    service: 'tikka-backend',
    storage: 'netlify-blobs',
    time: new Date().toISOString()
  });
});

/* =========================
   CONFIG
========================= */

app.get('/api/config', (req, res) => {
  res.json({
    success: true,
    shamCashNumber:
      process.env.SHAM_CASH_NUMBER ||
      'ضع رقم محفظتك هنا'
  });
});

/* =========================
   REGISTER
========================= */

app.post(
  '/api/auth/register',
  async (req, res) => {
    try {
      const {
        name,
        email,
        password
      } = req.body || {};

      if (
        !name ||
        !email ||
        !password ||
        String(password).length < 6
      ) {
        return res.status(400).json({
          success: false,
          message:
            'الاسم والبريد وكلمة السر (6 أحرف على الأقل) مطلوبة'
        });
      }

      const users = await read('users');

      const normalizedEmail =
        String(email)
          .trim()
          .toLowerCase();

      if (
        users.some(
          user =>
            user.email === normalizedEmail
        )
      ) {
        return res.status(409).json({
          success: false,
          message: 'البريد مستخدم مسبقاً'
        });
      }

      const user = {
        id: id('USR'),
        name: String(name).trim(),
        email: normalizedEmail,
        passwordHash:
          await bcrypt.hash(
            String(password),
            12
          ),
        role: 'customer',
        createdAt:
          new Date().toISOString()
      };

      users.push(user);

      await write('users', users);

      return res.status(201).json({
        success: true,
        user: safeUser(user),
        token: token(user)
      });
    } catch (error) {
      console.error(
        'REGISTER ERROR:',
        error
      );

      return res.status(500).json({
        success: false,
        message: 'حدث خطأ أثناء إنشاء الحساب'
      });
    }
  }
);

/* =========================
   LOGIN
========================= */

app.post(
  '/api/auth/login',
  async (req, res) => {
    try {
      const {
        email,
        password
      } = req.body || {};

      const users = await read('users');

      const normalizedEmail =
        String(email || '')
          .trim()
          .toLowerCase();

      const user = users.find(
        item =>
          item.email === normalizedEmail
      );

      if (
        !user ||
        !(await bcrypt.compare(
          String(password || ''),
          user.passwordHash
        ))
      ) {
        return res.status(401).json({
          success: false,
          message:
            'البريد أو كلمة السر غير صحيحة'
        });
      }

      return res.json({
        success: true,
        user: safeUser(user),
        token: token(user)
      });
    } catch (error) {
      console.error(
        'LOGIN ERROR:',
        error
      );

      return res.status(500).json({
        success: false,
        message: 'حدث خطأ أثناء تسجيل الدخول'
      });
    }
  }
);

/* =========================
   CURRENT USER
========================= */

app.get(
  '/api/auth/me',
  auth,
  async (req, res) => {
    try {
      const users = await read('users');

      const user = users.find(
        item =>
          item.id === req.user.id
      );

      return res.json({
        success: !!user,
        user: safeUser(user)
      });
    } catch {
      return res.status(500).json({
        success: false,
        message: 'حدث خطأ في السيرفر'
      });
    }
  }
);

/* =========================
   CREATE ORDER
========================= */

app.post(
  '/api/orders',
  async (req, res) => {
    try {
      const body = req.body || {};

      if (
        !body.customerName ||
        !body.phone ||
        !Array.isArray(body.items) ||
        !body.items.length
      ) {
        return res.status(400).json({
          success: false,
          message: 'بيانات الطلب ناقصة'
        });
      }

      const isShamCash =
        body.payment === 'Sham Cash' ||
        body.payment === 'shamcash';

      if (isShamCash) {
        const transactionId = String(
          body.transactionId ||
          body.txId ||
          ''
        ).trim();

        if (!transactionId) {
          return res.status(400).json({
            success: false,
            message:
              'رقم عملية شام كاش مطلوب'
          });
        }
      }

      const subtotal = Number(
        body.subtotal ??
        body.items.reduce(
          (sum, item) =>
            sum +
            Number(item.price || 0) *
              Number(
                item.quantity ||
                item.qty ||
                1
              ),
          0
        )
      );

      const deliveryFee = Number(
        body.deliveryFee || 0
      );

      const discount = Number(
        body.discount || 0
      );

      const total = Math.max(
        0,
        Number(
          body.total ??
            subtotal +
              deliveryFee -
              discount
        )
      );

      const now =
        new Date().toISOString();

      const order = {
        orderId: id('TIKKA'),

        userId:
          body.userId || null,

        customerName:
          String(body.customerName),

        phone:
          String(body.phone),

        address:
          String(body.address || ''),

        delivery:
          body.delivery ||
          body.deliveryMethod ||
          'pickup',

        deliveryNotes:
          String(
            body.deliveryNotes || ''
          ),

        payment:
          body.payment || 'cod',

        paymentStatus:
          body.paymentStatus ||
          (
            isShamCash
              ? 'بانتظار التحقق'
              : 'الدفع عند الاستلام'
          ),

        transactionId:
          String(
            body.transactionId ||
            body.txId ||
            '—'
          ),

        items:
          body.items.map(item => ({
            name:
              String(item.name),

            quantity:
              Number(
                item.quantity ||
                item.qty ||
                1
              ),

            price:
              Number(
                item.price || 0
              ),

            total:
              Number(
                item.total ??
                  Number(
                    item.price || 0
                  ) *
                    Number(
                      item.quantity ||
                      item.qty ||
                      1
                    )
              )
          })),

        subtotal,
        deliveryFee,
        discount,
        total,

        status: 'new',

        createdAt: now,
        updatedAt: now
      };

      const orders =
        await read('orders');

      orders.unshift(order);

      await write(
        'orders',
        orders
      );

      return res.status(201).json({
        success: true,
        message:
          'تم حفظ الطلب بنجاح',
        order
      });
    } catch (error) {
      console.error(
        'ORDER ERROR:',
        error
      );

      return res.status(500).json({
        success: false,
        message:
          'حدث خطأ أثناء حفظ الطلب'
      });
    }
  }
);

/* =========================
   GET ORDERS
========================= */

app.get(
  '/api/orders',
  auth,
  async (req, res) => {
    const orders =
      await read('orders');

    let result = orders;

    if (req.user.role !== 'admin') {
      result = orders.filter(
        order =>
          order.userId ===
            req.user.id ||
          order.phone ===
            req.query.phone
      );
    }

    res.json({
      success: true,
      orders: result
    });
  }
);

/* =========================
   GET SINGLE ORDER
========================= */

app.get(
  '/api/orders/:id',
  auth,
  async (req, res) => {
    const orders =
      await read('orders');

    const order = orders.find(
      item =>
        item.orderId ===
        req.params.id
    );

    if (!order) {
      return res.status(404).json({
        success: false,
        message: 'الطلب غير موجود'
      });
    }

    if (
      req.user.role !== 'admin' &&
      order.userId !== req.user.id
    ) {
      return res.status(403).json({
        success: false,
        message: 'غير مصرح'
      });
    }

    res.json({
      success: true,
      order
    });
  }
);

/* =========================
   ADMIN ORDERS
========================= */

app.get(
  '/api/admin/orders',
  auth,
  admin,
  async (req, res) => {
    const orders =
      await read('orders');

    res.json({
      success: true,
      orders
    });
  }
);

/* =========================
   UPDATE ORDER STATUS
========================= */

app.patch(
  '/api/orders/:id/status',
  auth,
  admin,
  async (req, res) => {
    const allowed = [
      'new',
      'confirmed',
      'preparing',
      'ready',
      'out_for_delivery',
      'delivered',
      'cancelled'
    ];

    if (
      !allowed.includes(
        req.body.status
      )
    ) {
      return res.status(400).json({
        success: false,
        message:
          'حالة الطلب غير صحيحة'
      });
    }

    const orders =
      await read('orders');

    const order = orders.find(
      item =>
        item.orderId ===
        req.params.id
    );

    if (!order) {
      return res.status(404).json({
        success: false,
        message: 'الطلب غير موجود'
      });
    }

    order.status =
      req.body.status;

    order.updatedAt =
      new Date().toISOString();

    await write(
      'orders',
      orders
    );

    res.json({
      success: true,
      order
    });
  }
);

/* =========================
   UPDATE PAYMENT STATUS
========================= */

app.patch(
  '/api/orders/:id/payment',
  auth,
  admin,
  async (req, res) => {
    const allowed = [
      'بانتظار الدفع',
      'بانتظار التحقق',
      'تم التحقق',
      'مرفوض',
      'الدفع عند الاستلام'
    ];

    if (
      !allowed.includes(
        req.body.paymentStatus
      )
    ) {
      return res.status(400).json({
        success: false,
        message:
          'حالة الدفع غير صحيحة'
      });
    }

    const orders =
      await read('orders');

    const order = orders.find(
      item =>
        item.orderId ===
        req.params.id
    );

    if (!order) {
      return res.status(404).json({
        success: false,
        message: 'الطلب غير موجود'
      });
    }

    order.paymentStatus =
      req.body.paymentStatus;

    order.updatedAt =
      new Date().toISOString();

    await write(
      'orders',
      orders
    );

    res.json({
      success: true,
      order
    });
  }
);

/* =========================
   ADMIN STATS
========================= */

app.get(
  '/api/admin/stats',
  auth,
  admin,
  async (req, res) => {
    const orders =
      await read('orders');

    const users =
      await read('users');

    const customers =
      users.filter(
        user =>
          user.role ===
          'customer'
      );

    const pending =
      orders.filter(
        order =>
          ![
            'delivered',
            'cancelled'
          ].includes(
            order.status
          )
      );

    const revenue =
      orders
        .filter(
          order =>
            order.status !==
            'cancelled'
        )
        .reduce(
          (sum, order) =>
            sum +
            Number(
              order.total || 0
            ),
          0
        );

    res.json({
      success: true,

      stats: {
        orders:
          orders.length,

        pending:
          pending.length,

        revenue,

        customers:
          customers.length
      }
    });
  }
);

/* =========================
   CHAT
========================= */

app.post(
  '/api/chat',
  async (req, res) => {
    const message = String(
      req.body.message || ''
    ).slice(0, 2000);

    if (!message) {
      return res.status(400).json({
        success: false,
        message:
          'الرسالة فارغة'
      });
    }

    const item = {
      id: id('MSG'),

      name:
        String(
          req.body.name ||
            'زائر'
        ),

      phone:
        String(
          req.body.phone || ''
        ),

      message,

      createdAt:
        new Date().toISOString()
    };

    const messages =
      await read('messages');

    messages.push(item);

    await write(
      'messages',
      messages
    );

    res.status(201).json({
      success: true,
      message: item
    });
  }
);

/* =========================
   ADMIN MESSAGES
========================= */

app.get(
  '/api/admin/messages',
  auth,
  admin,
  async (req, res) => {
    const messages =
      await read('messages');

    res.json({
      success: true,
      messages:
        messages
          .slice(-200)
          .reverse()
    });
  }
);

/* =========================
   ORDER PDF
========================= */

app.get(
  '/api/orders/:id/pdf',
  auth,
  admin,
  async (req, res) => {
    const orders =
      await read('orders');

    const order = orders.find(
      item =>
        item.orderId ===
        req.params.id
    );

    if (!order) {
      return res.status(404).json({
        success: false,
        message:
          'الطلب غير موجود'
      });
    }

    const doc =
      new PDFDocument({
        size: 'A4',
        margin: 50
      });

    res.setHeader(
      'Content-Type',
      'application/pdf'
    );

    res.setHeader(
      'Content-Disposition',
      `inline; filename="${order.orderId}.pdf"`
    );

    doc.pipe(res);

    doc
      .fontSize(20)
      .text(
        'TIKKA ORDER',
        {
          align: 'center'
        }
      );

    doc.moveDown();

    doc
      .fontSize(11)
      .text(
        `Order ID: ${order.orderId}`
      );

    doc.text(
      `Customer: ${order.customerName}`
    );

    doc.text(
      `Phone: ${order.phone}`
    );

    doc.text(
      `Address: ${order.address}`
    );

    doc.text(
      `Delivery: ${order.delivery}`
    );

    doc.text(
      `Payment: ${order.payment}`
    );

    doc.text(
      `Payment status: ${order.paymentStatus}`
    );

    doc.text(
      `Transaction ID: ${order.transactionId}`
    );

    doc.moveDown();

    doc
      .fontSize(14)
      .text('Items');

    doc.moveDown(0.5);

    order.items.forEach(
      (item, index) => {
        doc
          .fontSize(11)
          .text(
            `${index + 1}. ${
              item.name
            } x ${
              item.quantity
            } = ${
              Number(
                item.total || 0
              ).toLocaleString()
            } SYP`
          );
      }
    );

    doc.moveDown();

    doc
      .fontSize(12)
      .text(
        `Subtotal: ${Number(
          order.subtotal || 0
        ).toLocaleString()} SYP`
      );

    doc.text(
      `Delivery: ${Number(
        order.deliveryFee || 0
      ).toLocaleString()} SYP`
    );

    doc.text(
      `Discount: ${Number(
        order.discount || 0
      ).toLocaleString()} SYP`
    );

    doc
      .fontSize(15)
      .text(
        `TOTAL: ${Number(
          order.total || 0
        ).toLocaleString()} SYP`
      );

    doc.moveDown();

    doc
      .fontSize(9)
      .text(
        `Created: ${order.createdAt}`
      );

    doc.end();
  }
);

/* =========================
   ADMIN PAGE
========================= */

app.get(
  '/admin',
  (req, res) => {
    res.sendFile(
      path.join(
        ROOT,
        'public',
        'admin.html'
      )
    );
  }
);

/* =========================
   404
========================= */

app.use(
  (req, res) => {
    res.status(404).json({
      success: false,
      message:
        'المسار غير موجود'
    });
  }
);

/* =========================
   ERROR HANDLER
========================= */

app.use(
  (error, req, res, next) => {
    console.error(
      'SERVER ERROR:',
      error
    );

    res.status(500).json({
      success: false,
      message:
        'حدث خطأ في السيرفر'
    });
  }
);

/* =========================
   LOCAL / NETLIFY
========================= */

if (require.main === module) {
  ensureAdmin()
    .then(() => {
      app.listen(
        PORT,
        () => {
          console.log(
            `Tikka Backend يعمل على http://localhost:${PORT}`
          );
        }
      );
    })
    .catch(error => {
      console.error(
        'STARTUP ERROR:',
        error
      );

      process.exit(1);
    });
} else {
  // Netlify Function
  // Ensure the admin exists before handling requests.
  app.use(
    async (req, res, next) => {
      try {
        await ensureAdmin();
        next();
      } catch (error) {
        console.error(
          'NETLIFY INIT ERROR:',
          error
        );

        res.status(500).json({
          success: false,
          message:
            'تعذر تهيئة قاعدة بيانات Tikka'
        });
      }
    }
  );
}

module.exports = app;
