import express from 'express';
import Stripe from 'stripe';
import dotenv from 'dotenv';
import { Low } from 'lowdb';
import { JSONFile } from 'lowdb/node';
import multer from 'multer';
import multerS3 from 'multer-s3';
import { S3Client, PutObjectCommand, GetObjectCommand } from '@aws-sdk/client-s3';
import fs from 'fs';
import crypto from 'crypto';

dotenv.config();

// ensure uploads dir exists
// if (!fs.existsSync('public/uploads')) fs.mkdirSync('public/uploads', { recursive: true });

const s3 = new S3Client({ region: process.env.AWS_REGION, credentials: { accessKeyId: process.env.AWS_ACCESS_KEY, secretAccessKey: process.env.AWS_SECRET_KEY } });
const storage = multerS3({
  s3,
  bucket: process.env.S3_BUCKET_NAME,
  acl: 'public-read',
  contentType: multerS3.AUTO_CONTENT_TYPE,
  key: (req, file, cb) => {
    // Sanitize filename: replace spaces and any unsafe characters
    const safeName = file.originalname.replace(/[^a-zA-Z0-9._-]/g, '_');
    const key = Date.now() + '-' + safeName;
    cb(null, key);
  }
});
const upload = multer({ storage });

// helpers
const uploadFields = upload.fields([
  { name: 'image1', maxCount: 1 },
  { name: 'image2', maxCount: 1 },
  { name: 'media', maxCount: 1 }
]);

function filesToMedia(req) {
  const media = [];
  ['image1', 'image2', 'media'].forEach(key => {
    if (req.files && req.files[key] && req.files[key][0]) {
      const f = req.files[key][0];
      const url = `https://${process.env.S3_BUCKET_NAME}.s3.${process.env.AWS_REGION}.amazonaws.com/${f.key}`;
      const type = f.mimetype.startsWith('video') || f.mimetype === 'image/gif' ? 'video' : 'image';
      media.push({ url, type });
    }
  });
  return media;
}

const app = express();
app.use(express.json());
app.use(express.static('public'));

// Setup DB (simple JSON DB for demo)
// Use persistent disk on Render if mounted at /data; fallback to local file for dev
const DB_PATH = process.env.DB_PATH || (fs.existsSync('/data') ? '/data/db.json' : 'db.json');
const adapter = new JSONFile(DB_PATH);
const db = new Low(adapter, { products: [], orders: [] });
await db.read();
if (!db.data) { db.data = { products: [], orders: [] }; }
db.data.products ||= [];
db.data.orders ||= [];
db.data.interactions ||= {};
db.data.subscribers ||= [];

// try load persisted db.json from S3 so data survives restarts without paid disk
async function fetchRemoteDb() {
  try {
    const obj = await s3.send(new GetObjectCommand({
      Bucket: process.env.S3_BUCKET_NAME,
      Key: 'db.json'
    }));
    const chunks = [];
    for await (const chunk of obj.Body) chunks.push(chunk);
    fs.writeFileSync('db.json', Buffer.concat(chunks));
    console.log('Loaded db.json from S3');
  } catch (err) {
    console.log('No remote db.json found – starting fresh');
  }
}
await fetchRemoteDb();

// save locally then push copy to S3
const saveDb = async () => {
  await db.write();
  try {
    const data = fs.readFileSync('db.json');
    await s3.send(new PutObjectCommand({
      Bucket: process.env.S3_BUCKET_NAME,
      Key: 'db.json',
      Body: data,
      ACL: 'private',
      ContentType: 'application/json'
    }));
  } catch (e) { console.error('Failed to upload db.json', e); }
};

// encryption helpers
const ENC_SECRET = process.env.SUB_SECRET || 'default_sub_secret_key_please_change';
const key = crypto.createHash('sha256').update(String(ENC_SECRET)).digest(); // 32 bytes
function encrypt(text) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const enc = Buffer.concat([cipher.update(text, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return { iv: iv.toString('hex'), tag: tag.toString('hex'), data: enc.toString('hex') };
}

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);

// Admin – Add product & price
app.post('/api/products', uploadFields, async (req, res) => {
  try {
    const { name, description, unitAmount, estimatedTime, category, cost } = req.body;
    const media = filesToMedia(req);
    if (media.filter(m => m.type === 'image').length < 2) {
      return res.status(400).json({ error: 'At least two images required' });
    }
    const imageUrl = media.find(m => m.type === 'image')?.url;
    if (!name || !unitAmount) {
      return res.status(400).json({ error: 'Missing fields' });
    }

    // 1. Stripe Product
    const productData = { name, description };
    if (imageUrl) productData.images = media.filter(m => m.type === 'image').slice(0, 2).map(m => m.url);
    const stripeProduct = await stripe.products.create(productData);

    // 2. Stripe Price
    const price = await stripe.prices.create({
      product: stripeProduct.id,
      unit_amount: unitAmount,
      currency: 'usd',
      ...(imageUrl && { metadata: { imageUrl } })
    });

    // 3. Save locally
    const product = {
      id: stripeProduct.id,
      name: req.body.name,
      priceId: price.id,
      unitAmount: Number(req.body.unitAmount),
      currency: 'usd',
      image: media.find(m => m.type === 'image')?.url,
      media,
      estimatedTime: Number(req.body.estimatedTime || 0),
      category: req.body.category || 'Desserts',
      stock: true,
      cost: req.body.cost ? Number(req.body.cost) : 0
    };
    db.data.products.push(product);
    await saveDb();

    res.json(product);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

// Admin – Create Deal (bundle of two products)
app.post('/api/deals', uploadFields, async (req, res) => {
  try {
    const { prod1Id, prod2Id, unitAmount } = req.body;
    if (!prod1Id || !prod2Id || !unitAmount) return res.status(400).json({ error: 'missing fields' });
    await db.read();
    const p1 = db.data.products.find(p => p.id === prod1Id);
    const p2 = db.data.products.find(p => p.id === prod2Id);
    if (!p1 || !p2) return res.status(404).json({ error: 'product not found' });
    const name = `${p1.name} + ${p2.name} Deal`;

    // create stripe product & price
    const stripeProduct = await stripe.products.create({ name });
    const price = await stripe.prices.create({ product: stripeProduct.id, unit_amount: Math.round(Number(unitAmount) * 100), currency: 'usd' });

    const media = filesToMedia(req);
    let image = media.find(m => m.type === 'image')?.url;
    if (!image) image = p1.image || p2.image;

    const deal = {
      id: stripeProduct.id,
      name,
      priceId: price.id,
      unitAmount: Math.round(Number(unitAmount) * 100),
      currency: 'usd',
      image,
      media: media.length ? media : [{ url: image, type: 'image' }],
      estimatedTime: (p1.estimatedTime || 0) + (p2.estimatedTime || 0),
      stock: true,
      category: 'Deals',
      isDeal: true,
      originalPrice: (p1.unitAmount + p2.unitAmount) / 100,
      cost: (p1.cost || 0) + (p2.cost || 0)
    };
    db.data.products.push(deal);
    await saveDb();
    res.json(deal);
  } catch (e) { console.error(e); res.status(500).json({ error: 'server' }); }
});

// Get products for storefront
app.get('/api/products', async (_req, res) => {
  await db.read();
  const all = _req.query.all === '1';
  const prods = all ? db.data.products : db.data.products.filter(p => p.stock !== false);
  res.json(prods);
});

// Update / toggle product
app.patch('/api/products/:id', uploadFields, async (req, res) => {
  await db.read();
  const prod = db.data.products.find(p => p.id === req.params.id);
  if (!prod) return res.status(404).json({ error: 'not found' });
  const { estimatedTime, category, cost, ...rest } = req.body;
  Object.assign(prod, rest);
  if (estimatedTime !== undefined) prod.estimatedTime = Number(estimatedTime);
  if (category !== undefined) prod.category = category;
  if (cost !== undefined) prod.cost = Number(cost);
  const media = filesToMedia(req);
  if (media.length) {
    prod.media = [...(prod.media || []), ...media];
    const firstImg = [...media, ...(prod.media || [])].find(m => m.type === 'image');
    if (firstImg) prod.image = firstImg.url;
  }
  // if unitAmount changed, create new price in Stripe
  if (req.body.unitAmount && Number(req.body.unitAmount) !== prod.unitAmount) {
    const newPrice = await stripe.prices.create({ product: prod.id, unit_amount: Number(req.body.unitAmount), currency: 'usd' });
    prod.priceId = newPrice.id;
    prod.unitAmount = Number(req.body.unitAmount);
  }
  await saveDb();
  res.json(prod);
});

// Delete product
app.delete('/api/products/:id', async (req, res) => {
  await db.read();
  db.data.products = db.data.products.filter(p => p.id !== req.params.id);
  await saveDb();
  res.json({ success: true });
});

// Checkout
app.post('/api/checkout', async (req, res) => {
  try {
    const { items, priceId, quantity } = req.body;

    // Normalize items to array of objects with priceId & quantity
    let orderItems;
    let line_items;
    if (Array.isArray(items) && items.length) {
      line_items = items.map(i => ({ price: i.priceId, quantity: i.quantity || 1 }));
      orderItems = items;
    } else {
      line_items = [{ price: priceId, quantity: quantity || 1 }];
      orderItems = [{ priceId, quantity: quantity || 1 }];
    }

    // ensure each item has name
    orderItems = orderItems.map(it => {
      if (it.name) return it;
      const prod = db.data.products.find(p => p.priceId === it.priceId);
      return { ...it, name: prod ? prod.name : 'Item' };
    });

    const session = await stripe.checkout.sessions.create({
      mode: 'payment',
      line_items,
      success_url: `${req.headers.origin}/success.html?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${req.headers.origin}/cancel.html`
    });

    // calculate prep time
    let prep = 0;
    orderItems.forEach(it => {
      const prod = db.data.products.find(p => p.priceId === it.priceId);
      if (prod && prod.estimatedTime) prep += prod.estimatedTime * (it.quantity || 1);
    });

    // Save order locally with pending status
    const order = {
      id: Date.now(),
      sessionId: session.id,
      items: orderItems,
      status: 'pending',
      created: Date.now(),
      prepMinutes: prep
    };
    db.data.orders.push(order);
    await saveDb();

    res.json({ url: session.url, sessionId: session.id });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

// Webhook endpoint (optional – not used in demo UI)
app.post('/webhook', express.raw({ type: 'application/json' }), async (req, res) => {
  const sig = req.headers['stripe-signature'];
  let event;
  try {
    event = stripe.webhooks.constructEvent(req.body, sig, process.env.STRIPE_WEBHOOK_SECRET);
  } catch (err) {
    console.error('Webhook signature verification failed', err.message);
    return res.sendStatus(400);
  }
  if (event.type === 'checkout.session.completed') {
    console.log('Payment complete:', event.data.object.id);
    const sessionId = event.data.object.id;
    await db.read();
    const order = db.data.orders.find(o => o.sessionId === sessionId);
    if (order) {
      order.status = 'paid';
      await saveDb();
    }
  }
  res.sendStatus(200);
});

// Customer fetch single order status
app.get('/api/order-status/:sessionId', async (req, res) => {
  await db.read();
  const order = db.data.orders.find(o => o.sessionId === req.params.sessionId);
  if (!order) return res.status(404).json({ error: 'not found' });
  res.json(order);
});

// Cashier API
app.get('/api/orders', async (_req, res) => {
  await db.read();
  if (!db.data) db.data = { products: [], orders: [] };
  db.data.orders ||= [];
  res.json(db.data.orders.filter(o => o.status === 'paid'));
});

app.post('/api/orders/:id/done', async (req, res) => {
  await db.read();
  if (!db.data) db.data = { products: [], orders: [] };
  db.data.orders ||= [];
  const order = db.data.orders.find(o => String(o.id) === req.params.id);
  if (order) {
    order.status = 'done';
    await saveDb();
    return res.json({ success: true });
  }
  res.status(404).json({ error: 'Order not found' });
});

// Fallback for when webhooks not configured: mark order paid via client
app.post('/api/session-complete', async (req, res) => {
  const { sessionId } = req.body;
  if (!sessionId) return res.status(400).json({ error: 'sessionId required' });
  await db.read();
  if (!db.data) db.data = { products: [], orders: [] };
  const order = db.data.orders.find(o => o.sessionId === sessionId);
  if (order) { 
    order.status = 'paid'; 
    await saveDb(); 
    return res.json({ success: true }); 
  }
  res.status(404).json({ error: 'Order not found' });
});

app.post('/api/track-view', async (req, res) => {
  const { productId } = req.body;
  if (!productId) return res.sendStatus(400);
  await db.read();
  function incInteraction(pid, field) {
    db.data.interactions ||= {};
    db.data.interactions[pid] ||= { views: 0, adds: 0 };
    db.data.interactions[pid][field]++;
  }
  incInteraction(productId, 'views');
  await saveDb();
  res.sendStatus(200);
});

app.post('/api/track-add', async (req, res) => {
  const { productId } = req.body;
  if (!productId) return res.sendStatus(400);
  await db.read();
  function incInteraction(pid, field) {
    db.data.interactions ||= {};
    db.data.interactions[pid] ||= { views: 0, adds: 0 };
    db.data.interactions[pid][field]++;
  }
  incInteraction(productId, 'adds');
  await saveDb();
  res.sendStatus(200);
});

app.get('/api/interaction-data', async (_req, res) => {
  await db.read();
  const list = db.data.products.map(p => {
    const data = db.data.interactions[p.id] || { views: 0, adds: 0 };
    return { id: p.id, name: p.name, views: data.views, adds: data.adds, estimatedTime: p.estimatedTime || 0 };
  });
  res.json(list);
});

// Simple 30-day revenue / product analytics
app.get('/api/stripe-summary', async (_req, res) => {
  try {
    const since = Math.floor(Date.now() / 1000) - 30 * 24 * 60 * 60;
    const charges = await stripe.charges.list({ limit: 100, created: { gte: since }, paid: true });
    let gross = 0, refunded = 0;
    charges.data.forEach(c => { gross += c.amount; refunded += c.amount_refunded; });
    // product counts from local orders (last 30d)
    await db.read();
    const counts = {}; let profit = 0;
    db.data.orders.filter(o => o.created >= since * 1000 && (o.status === 'paid' || o.status === 'done')).forEach(o => {
      o.items.forEach(it => {
        counts[it.name] = (counts[it.name] || 0) + (it.quantity || 1);
        const prod = db.data.products.find(p => p.priceId === it.priceId);
        if (prod) { profit += ((it.unitAmount || prod.unitAmount) - (prod.cost || 0)) * (it.quantity || 1); }
      });
    });
    res.json({ gross: gross / 100, refunds: refunded / 100, net: (gross - refunded) / 100, profit: profit / 100, counts });
  } catch (e) { console.error(e); res.status(500).json({ error: 'stripe error' }); }
});

// Detailed insights last 30 days
app.get('/api/insights', async (_req, res) => {
  try {
    const since = Math.floor(Date.now() / 1000) - 30 * 24 * 60 * 60;
    const charges = await stripe.charges.list({ limit: 100, created: { gte: since }, paid: true });
    const daily = {}, weekly = {}, customerCounts = {}, customers = {};
    let grossMap = {};
    charges.data.forEach(c => {
      const d = new Date(c.created * 1000);
      const dayKey = d.toISOString().slice(0, 10);
      daily[dayKey] = (daily[dayKey] || 0) + c.amount;
      const weekKey = `${d.getFullYear()}-W${getWeek(d)}`;
      weekly[weekKey] = (weekly[weekKey] || 0) + c.amount;
      customers[c.customer] = (customers[c.customer] || 0) + 1;
    });
    const newCust = Object.values(customers).filter(v => v === 1).length;
    const returning = Object.values(customers).filter(v => v > 1).length;

    await db.read();
    const counts = {}, revenueProd = {};
    const hourly = new Array(24).fill(0);
    const weekday = new Array(7).fill(0);
    db.data.orders.filter(o => o.created >= since * 1000).forEach(o => {
      const d = new Date(o.created);
      hourly[d.getHours()]++;
      weekday[d.getDay()]++;
      o.items.forEach(it => {
        counts[it.name] = (counts[it.name] || 0) + (it.quantity || 1);
        revenueProd[it.name] = (revenueProd[it.name] || 0) + (it.unitAmount || 0) * (it.quantity || 1);
      });
    });
    const top = Object.entries(counts).sort((a, b) => b[1] - a[1]).slice(0, 10).map(([name, qty]) => ({ name, qty, rev: (revenueProd[name] || 0) / 100 }));
    res.json({ daily, weekly, newCust, returning, hourly, weekday, top });
  } catch (e) { console.error(e); res.status(500).json({ error: 'insights error' }); }
});

function getWeek(d) {
  d = new Date(Date.UTC(d.getFullYear(), d.getMonth(), d.getDate()));
  d.setUTCDate(d.getUTCDate() + 4 - (d.getUTCDay() || 7));
  const yearStart = new Date(Date.UTC(d.getUTCFullYear(), 0, 1));
  const weekNo = Math.ceil((((d - yearStart) / 86400000) + 1) / 7);
  return weekNo;
}

// History last 24h
app.get('/api/orders/history', async (_req, res) => {
  await db.read();
  const since = Date.now() - 24 * 60 * 60 * 1000;
  const list = db.data.orders.filter(o => o.created >= since).sort((a, b) => b.created - a.created);
  res.json(list);
});

// Refund order
app.post('/api/orders/:id/refund', async (req, res) => {
  await db.read();
  const order = db.data.orders.find(o => o.id == req.params.id);
  if (!order) return res.status(404).json({ error: 'not found' });
  if (order.refunded) return res.json({ status: 'already' });
  try {
    const session = await stripe.checkout.sessions.retrieve(order.sessionId, { expand: ['payment_intent'] });
    const pi = session.payment_intent;
    await stripe.refunds.create({ payment_intent: pi.id });
    order.refunded = true;
    order.status = 'refunded';
    await saveDb();
    res.json({ status: 'refunded' });
  } catch (e) { console.error(e); res.status(500).json({ error: 'stripe refund error' }); }
});

app.post('/api/subscribe', async (req, res) => {
  const { email, phone } = req.body;
  if (!email && !phone) return res.status(400).json({ error: 'missing' });
  await db.read();
  const enc = {
    email: email ? encrypt(email) : null,
    phone: phone ? encrypt(phone) : null,
    ts: Date.now()
  };
  db.data.subscribers.push(enc);
  await saveDb();
  res.json({ ok: true });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
