import { Request, Response, NextFunction } from 'express';  
import nodemailer from 'nodemailer';
import { createClient } from 'redis';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import dotenv from 'dotenv';
import { prisma } from './prismaClient.controller';

dotenv.config();

const redisClient = createClient({ url: process.env.REDIS_URL as string });
redisClient.connect().catch(err => console.error('Redis ulanish xatosi:', err));

const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

interface RedisData {
  code: string;
  hashedPassword: string;
}

const generateToken = (payload: object): string => {
  return jwt.sign(payload, process.env.JWT_SECRET as string, { expiresIn: '1h' });
};

const validateEmail = (email: string): boolean => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);

const validatePasswordStrength = (password: string): boolean => {
  const hasUpperCase = /[A-Z]/.test(password);
  const hasLowerCase = /[a-z]/.test(password);
  const hasDigit = /\d/.test(password);
  const hasSpecialChar = /[!@#$%^&*(),.?":{}|<>]/.test(password);
  
  return password.length >= 8 && hasUpperCase && hasLowerCase && hasDigit && hasSpecialChar;
};

const authenticateToken = (req: Request, res: Response, next: NextFunction) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader?.startsWith('Bearer ') ? authHeader.split(' ')[1] : null;

  if (!token) return res.status(401).json({ success: false, message: 'Token kerak' });

  jwt.verify(token, process.env.JWT_SECRET as string, (err, user) => {
    if (err) return res.status(403).json({ success: false, message: 'Token noto\'g\'ri' });
    req.user = user as jwt.JwtPayload;
    next();
  });
};

const isJwtPayload = (user: any): user is jwt.JwtPayload => {
  return typeof user === 'object' && user !== null && 'email' in user;
};

export class AuthController {
  static async register(req: Request, res: Response, next: NextFunction) {
    const { email, password } = req.body;

    try {
      if (!email || !password) {
        return res.status(400).json({ success: false, message: 'Email va parol kerak' });
      }

      if (!validateEmail(email)) {
        return res.status(400).json({ success: false, message: 'Email format noto\'g\'ri' });
      }

      if (!validatePasswordStrength(password)) {
        return res.status(400).json({ success: false, message: 'Parol kuch talablariga javob bermaydi' });
      }

      const existingUser = await prisma.user.findUnique({
        where: { email },
      });

      if (existingUser) {
        return res.status(400).json({ success: false, message: 'Email allaqachon ro\'yxatdan o\'tgan' });
      }

      const hashedPassword = await bcrypt.hash(password, 10);
      const code = (Math.floor(100000 + Math.random() * 900000)).toString();

      await redisClient.setEx(email, 300, JSON.stringify({ code, hashedPassword }));

      await transporter.sendMail({
        from: process.env.EMAIL_USER,
        to: email,
        subject: 'Email Tasdiqlash Kodi',
        text: `Sizning tasdiqlash kodingiz ${code}`,
        html: `
        <h1>Xush kelibsiz!</h1>
        <p>Sizning tasdiqlash kodingiz <b>${code}</b></p>
        <p>Emailingizni tasdiqlash uchun yuqoridagi kodni ishlating.</p>
    `,
      });

      res.status(200).json({
        success: true,
        message: 'Tasdiqlash kodi sizning emailingizga yuborildi',
      });
    } catch (err) {
      console.error('Ro\'yxatdan o\'tishda xato:', err);
      next(err);
    }
  }

  static async verify(req: Request, res: Response, next: NextFunction) {
    const { email, code } = req.body;

    try {
      if (!email || !code) {
        return res.status(400).json({ success: false, message: 'Email va kod kerak' });
      }

      const storedData = await redisClient.get(email);

      if (!storedData) {
        return res.status(400).json({ success: false, message: 'Kod muddati o\'tdi yoki topilmadi' });
      }

      const { code: redisCode, hashedPassword }: RedisData = JSON.parse(storedData);

      if (code !== redisCode) {
        return res.status(400).json({ success: false, message: 'Noto\'g\'ri kod' });
      }

      // Foydalanuvchini Prisma bazasiga qo'shish
      await prisma.user.create({
        data: {
          email,
          hashedPassword,
        },
      });

      const token = generateToken({ email });
      await redisClient.del(email);

      res.status(200).json({
        success: true,
        message: 'Muvaffaqiyatli ro\'yxatdan o\'tish',
        token,
      });
    } catch (err) {
      console.error('Tasdiqlashda xato:', err);
      next(err);
    }
  }

  static async login(req: Request, res: Response, next: NextFunction) {
    const { email, password } = req.body;

    try {
      if (!email || !password) {
        return res.status(400).json({ success: false, message: 'Email va parol kerak' });
      }

      if (!validateEmail(email)) {
        return res.status(400).json({ success: false, message: 'Email format noto\'g\'ri' });
      }

      // Foydalanuvchi ma'lumotlarini Prisma-dan olish
      const user = await prisma.user.findUnique({
        where: { email },
      });

      if (!user) {
        return res.status(400).json({ success: false, message: 'Email ro\'yxatda yo\'q' });
      }

      const isPasswordValid = await bcrypt.compare(password, user.hashedPassword);

      if (!isPasswordValid) {
        return res.status(400).json({ success: false, message: 'Noto\'g\'ri parol' });
      }

      const token = generateToken({ email });

      res.status(200).json({
        success: true,
        message: 'Tizimga kirish muvaffaqiyatli',
        token,
      });
    } catch (err) {
      console.error('Kirishda xato:', err);
      next(err);
    }
  }

  static async changePassword(req: Request, res: Response, next: NextFunction) {
    const { email, oldPassword, newPassword } = req.body;

    try {
      if (!email || !oldPassword || !newPassword) {
        return res.status(400).json({ success: false, message: 'Email, eski parol va yangi parol kerak' });
      }

      if (!validateEmail(email)) {
        return res.status(400).json({ success: false, message: 'Email format noto\'g\'ri' });
      }

      if (!validatePasswordStrength(newPassword)) {
        return res.status(400).json({ success: false, message: 'Yangi parol kuch talablariga javob bermaydi' });
      }

      const user = await prisma.user.findUnique({
        where: { email },
      });

      if (!user) {
        return res.status(400).json({ success: false, message: 'Email ro\'yxatda yo\'q' });
      }

      const isOldPasswordValid = await bcrypt.compare(oldPassword, user.hashedPassword);

      if (!isOldPasswordValid) {
        return res.status(400).json({ success: false, message: 'Eski parol noto\'g\'ri' });
      }

      const hashedNewPassword = await bcrypt.hash(newPassword, 10);

      await prisma.user.update({
        where: { email },
        data: { hashedPassword: hashedNewPassword },
      });

      res.status(200).json({ success: true, message: 'Parol muvaffaqiyatli o\'zgartirildi' });
    } catch (err) {
      console.error('Parolni o\'zgartirishda xato:', err);
      next(err);
    }
  }

  static async forgotPassword(req: Request, res: Response, next: NextFunction) {
    const { email } = req.body;

    try {
      if (!email) {
        return res.status(400).json({ success: false, message: 'Email kerak' });
      }

      if (!validateEmail(email)) {
        return res.status(400).json({ success: false, message: 'Email format noto\'g\'ri' });
      }

      const user = await prisma.user.findUnique({
        where: { email },
      });

      if (!user) {
        return res.status(400).json({ success: false, message: 'Email ro\'yxatda yo\'q' });
      }

      const code = (Math.floor(100000 + Math.random() * 900000)).toString();

      await redisClient.setEx(`${email}-reset`, 300, code);

      await transporter.sendMail({
        from: process.env.EMAIL_USER,
        to: email,
        subject: 'Parolni Tiklash Kodi',
        text: `Sizning parolni tiklash kodingiz ${code}`,
        html: `
        <h1>Parolni tiklash kodi</h1>
        <p>Sizning parolni tiklash kodingiz <b>${code}</b></p>
        <p>Yuqoridagi kodni ishlatib parolingizni tiklang.</p>
    `,
      });

      res.status(200).json({ success: true, message: 'Parol tiklash kodi yuborildi' });
    } catch (err) {
      console.error('Parolni tiklashda xato:', err);
      next(err);
    }
  }

  static async resetPassword(req: Request, res: Response, next: NextFunction) {
    const { email, code, newPassword } = req.body;

    try {
      if (!email || !code || !newPassword) {
        return res.status(400).json({ success: false, message: 'Email, kod va yangi parol kerak' });
      }

      if (!validateEmail(email)) {
        return res.status(400).json({ success: false, message: 'Email format noto\'g\'ri' });
      }

      if (!validatePasswordStrength(newPassword)) {
        return res.status(400).json({ success: false, message: 'Yangi parol kuch talablariga javob bermaydi' });
      }

      const storedCode = await redisClient.get(`${email}-reset`);

      if (code !== storedCode) {
        return res.status(400).json({ success: false, message: 'Noto\'g\'ri kod' });
      }

      const hashedNewPassword = await bcrypt.hash(newPassword, 10);

      await prisma.user.update({
        where: { email },
        data: { hashedPassword: hashedNewPassword },
      });

      await redisClient.del(`${email}-reset`);

      res.status(200).json({ success: true, message: 'Parol muvaffaqiyatli o\'zgartirildi' });
    } catch (err) {
      console.error('Parolni tiklashda xato:', err);
      next(err);
    }
  }


  static async getProfile(req: Request, res: Response, next: NextFunction) {
    try {
      const user = req.user;
      
      if (!isJwtPayload(user)) {
        return res.status(401).json({ success: false, message: 'Noto\'g\'ri token ma\'lumotlari' });
      }
      
      const userData = await prisma.user.findUnique({
        where: { email: user.email },
        select: { email: true },
      });
      
      if (!userData) {
        return res.status(404).json({ success: false, message: 'Foydalanuvchi topilmadi' });
      }
      
      res.status(200).json({
        success: true,
        user: userData,
      });
    } catch (err) {
      console.error('Profilni olishda xato:', err);
      next(err);
    }
  }


}








