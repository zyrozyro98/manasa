const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const cloudinary = require('cloudinary').v2;
const { CloudinaryStorage } = require('multer-storage-cloudinary');
const cors = require('cors');
require('dotenv').config();

const app = express();

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static('public'));

// تكوين Cloudinary
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET
});

// تكوين MongoDB
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/student-platform', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

// نماذج البيانات
const UserSchema = new mongoose.Schema({
  fullName: { type: String, required: true },
  phone: { type: String, required: true, unique: true },
  university: { type: String, required: true },
  major: { type: String, required: true },
  batch: { type: String, required: true },
  password: { type: String, required: true },
  role: { type: String, default: 'student' }
}, { timestamps: true });

const MessageSchema = new mongoose.Schema({
  senderId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  receiverId: { type: String, default: 'admin' },
  text: { type: String, required: true },
  timestamp: { type: Date, default: Date.now }
});

const ImageSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  imageName: { type: String, required: true },
  url: { type: String, required: true },
  sentAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', UserSchema);
const Message = mongoose.model('Message', MessageSchema);
const Image = mongoose.model('Image', ImageSchema);

// Middleware المصادقة
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ message: 'الوصول مرفوض' });
  }

  jwt.verify(token, process.env.JWT_SECRET || 'secret', (err, user) => {
    if (err) {
      return res.status(403).json({ message: 'رمز غير صالح' });
    }
    req.user = user;
    next();
  });
};

// Middleware التحقق من صلاحيات المدير
const requireAdmin = (req, res, next) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ message: 'غير مصرح بالوصول' });
  }
  next();
};

// تكوين multer للرفع إلى Cloudinary
const storage = new CloudinaryStorage({
  cloudinary: cloudinary,
  params: {
    folder: 'student-platform',
    format: async (req, file) => 'png',
    public_id: (req, file) => {
      const phone = req.body.phone || 'unknown';
      return `${phone}-${Date.now()}`;
    }
  },
});

const upload = multer({ storage: storage });

// المسارات
app.post('/api/auth/register', async (req, res) => {
  try {
    const { fullName, phone, university, major, batch, password } = req.body;

    // التحقق من صحة رقم الهاتف السعودي
    const saudiPhoneRegex = /^5\d{8}$/;
    if (!saudiPhoneRegex.test(phone)) {
      return res.status(400).json({ message: 'رقم الهاتف غير صحيح' });
    }

    // التحقق من عدم وجود مستخدم بنفس الرقم
    const existingUser = await User.findOne({ phone });
    if (existingUser) {
      return res.status(400).json({ message: 'رقم الهاتف مسجل مسبقاً' });
    }

    // تشفير كلمة المرور
    const hashedPassword = await bcrypt.hash(password, 10);

    // إنشاء المستخدم
    const user = new User({
      fullName,
      phone,
      university,
      major,
      batch,
      password: hashedPassword
    });

    await user.save();

    res.status(201).json({ message: 'تم إنشاء الحساب بنجاح' });
  } catch (error) {
    res.status(500).json({ message: 'خطأ في الخادم' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { phone, password } = req.body;

    // البحث عن المستخدم
    const user = await User.findOne({ phone });
    if (!user) {
      return res.status(400).json({ message: 'رقم الهاتف أو كلمة المرور غير صحيحة' });
    }

    // التحقق من كلمة المرور
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(400).json({ message: 'رقم الهاتف أو كلمة المرور غير صحيحة' });
    }

    // إنشاء token
    const token = jwt.sign(
      { _id: user._id, role: user.role },
      process.env.JWT_SECRET || 'secret',
      { expiresIn: '7d' }
    );

    res.json({
      token,
      user: {
        _id: user._id,
        fullName: user.fullName,
        phone: user.phone,
        university: user.university,
        major: user.major,
        batch: user.batch,
        role: user.role
      }
    });
  } catch (error) {
    res.status(500).json({ message: 'خطأ في الخادم' });
  }
});

app.post('/api/chat/send', authenticateToken, async (req, res) => {
  try {
    const { text } = req.body;

    const message = new Message({
      senderId: req.user._id,
      text
    });

    await message.save();
    res.json({ message: 'تم إرسال الرسالة' });
  } catch (error) {
    res.status(500).json({ message: 'خطأ في الخادم' });
  }
});

app.get('/api/chat/messages', authenticateToken, async (req, res) => {
  try {
    const messages = await Message.find({
      $or: [
        { senderId: req.user._id },
        { receiverId: req.user._id }
      ]
    }).populate('senderId', 'fullName').sort({ timestamp: 1 });

    res.json(messages);
  } catch (error) {
    res.status(500).json({ message: 'خطأ في الخادم' });
  }
});

app.post('/api/admin/send-image', authenticateToken, requireAdmin, upload.single('image'), async (req, res) => {
  try {
    const { phone } = req.body;

    if (!req.file) {
      return res.status(400).json({ message: 'لم يتم رفع أي صورة' });
    }

    // البحث عن المستخدم باستخدام رقم الهاتف (اسم الملف)
    const user = await User.findOne({ phone });
    if (!user) {
      return res.status(404).json({ message: `لم يتم العثور على مستخدم بالرقم: ${phone}` });
    }

    // حفظ معلومات الصورة في قاعدة البيانات
    const image = new Image({
      userId: user._id,
      imageName: phone,
      url: req.file.path
    });

    await image.save();
    res.json({ message: 'تم إرسال الصورة بنجاح', image });
  } catch (error) {
    res.status(500).json({ message: 'خطأ في الخادم' });
  }
});

app.get('/api/images', authenticateToken, async (req, res) => {
  try {
    const images = await Image.find({ userId: req.user._id }).sort({ sentAt: -1 });
    res.json(images);
  } catch (error) {
    res.status(500).json({ message: 'خطأ في الخادم' });
  }
});

// إنشاء مدير افتراضي
const createAdminUser = async () => {
  try {
    const adminExists = await User.findOne({ role: 'admin' });
    if (!adminExists) {
      const hashedPassword = await bcrypt.hash('admin123', 10);
      const admin = new User({
        fullName: 'مدير النظام',
        phone: '500000000',
        university: 'الإدارة',
        major: 'الإدارة',
        batch: '2020',
        password: hashedPassword,
        role: 'admin'
      });
      await admin.save();
      console.log('تم إنشاء حساب المدير الافتراضي');
    }
  } catch (error) {
    console.error('خطأ في إنشاء المدير:', error);
  }
};

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`الخادم يعمل على المنفذ ${PORT}`);
  createAdminUser();
});