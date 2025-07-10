/* eslint-disable prettier/prettier */
import {
  Injectable,
  BadRequestException,
  UnauthorizedException,
} from '@nestjs/common';
import { UserService } from 'src/user/user.service';
import * as bcrypt from 'bcrypt';
import * as crypto from 'crypto';
import * as nodemailer from 'nodemailer';
import { JwtService } from '@nestjs/jwt';
import { Response } from 'express';

@Injectable()
export class AuthService {
  constructor(
    private userService: UserService,
    private jwtService: JwtService,
  ) {}

  async signup(email: string, password: string, name: string, dob: string) {
    const existing = await this.userService.findByEmail(email);
    if (existing) throw new BadRequestException('Email already exists');

    const passwordHash = await bcrypt.hash(password, 10);
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const otpExpiresAt = new Date(Date.now() + 5 * 60 * 1000); // 5 minutes

    const user = await this.userService.create({
      name,
      email,
      password: passwordHash,
      dob: new Date(dob),
      otp,
      otpExpiresAt,
    });

    await this.sendOtpEmail(user.email, otp, 'signup');
    return { message: 'OTP sent to email' };
  }

  async sendOtpEmail(
    to: string,
    otp: string,
    context: 'signup' | 'reset' | 'login',
  ) {
    const emailUser = process.env.EMAIL_USER;
    const emailPass = process.env.EMAIL_PASS;

    if (!emailUser || !emailPass) {
      throw new Error(
        'Missing EMAIL_USER or EMAIL_PASS in environment variables. Cannot send email.',
      );
    }

    const transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: emailUser,
        pass: emailPass,
      },
    });

    const subject =
      context === 'signup'
        ? 'Email Verification Code'
        : context === 'reset'
          ? 'Password Reset Code'
          : 'Login OTP Code';

    const text =
      context === 'signup'
        ? `Your verification code is ${otp}. It expires in 5 minutes.`
        : context === 'reset'
          ? `You requested to reset your password. Your OTP is ${otp}. It expires in 5 minutes.`
          : `Use this OTP to log in: ${otp}. It expires in 5 minutes.`;

    const mailOptions = {
      from: `"NoReply" <${emailUser}>`,
      to,
      subject,
      text,
    };

    await transporter.sendMail(mailOptions);
  }

  async verifyOtp(email: string, otp: string) {
    const user = await this.userService.findByEmail(email);
    if (!user) throw new BadRequestException('User not found');

    if (
      !user.otp ||
      user.otp !== otp ||
      !user.otpExpiresAt ||
      user.otpExpiresAt.getTime() < Date.now()
    ) {
      throw new BadRequestException('Invalid or expired OTP');
    }

    user.isEmailVerified = true;
    user.otp = undefined;
    user.otpExpiresAt = undefined;

    await user.save();
    return { message: 'Email verified successfully' };
  }

  async resendOtp(email: string) {
    const user = await this.userService.findByEmail(email);
    if (!user) throw new BadRequestException('User not found');

    if (user.isEmailVerified) {
      throw new BadRequestException('Email is already verified');
    }

    // Rate limit: 1 resend per 2 minutes
    const now = new Date();
    if (
      user.lastOtpSentAt &&
      now.getTime() - user.lastOtpSentAt.getTime() < 2 * 60 * 1000
    ) {
      throw new BadRequestException(
        'OTP already sent recently. Try again later.',
      );
    }

    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const otpExpiresAt = new Date(now.getTime() + 5 * 60 * 1000); // 5 minutes

    user.otp = otp;
    user.otpExpiresAt = otpExpiresAt;
    user.lastOtpSentAt = now;

    await user.save();
    await this.sendOtpEmail(user.email, otp, 'signup');

    return { message: 'New OTP sent to your email' };
  }

  async sendOtpForLogin(email: string) {
    const user = await this.userService.findByEmail(email);
    if (!user) throw new BadRequestException('User not found');

    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const otpExpiresAt = new Date(Date.now() + 5 * 60 * 1000); // 5 min

    user.otp = otp;
    user.otpExpiresAt = otpExpiresAt;
    await user.save();

    await this.sendOtpEmail(user.email, otp, 'login');

    return { message: 'OTP sent to email' };
  }

  async verifyOtpForLogin(email: string, otp: string, res: Response) {
    const user = await this.userService.findByEmail(email);
    if (!user) throw new BadRequestException('User not found');

    if (
      !user.otp ||
      user.otp !== otp ||
      !user.otpExpiresAt ||
      user.otpExpiresAt.getTime() < Date.now()
    ) {
      throw new BadRequestException('Invalid or expired OTP');
    }

    // OTP is valid → clear it
    user.otp = undefined;
    user.otpExpiresAt = undefined;
    user.isEmailVerified = true;
    await user.save();

    // Generate tokens
    const accessToken = this.jwtService.sign(
      { email: user.email, sub: user._id },
      { expiresIn: '15m' },
    );

    const refreshToken = this.jwtService.sign(
      { email: user.email, sub: user._id },
      { expiresIn: '7d', secret: process.env.REFRESH_SECRET },
    );

    user.refreshTokens = [...(user.refreshTokens || []), refreshToken];
    await user.save();

    res.cookie('refresh_token', refreshToken, {
      httpOnly: true,
      sameSite: 'lax',
      secure: false,
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    return res.status(200).json({ accessToken });
  }

  async login(email: string, password: string, res: Response) {
    const user = await this.userService.findByEmail(email);
    if (!user || !user.password)
      throw new BadRequestException('Invalid credentials');

    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) throw new BadRequestException('Invalid credentials');

    if (!user.isEmailVerified)
      throw new BadRequestException('Email not verified');

    const accessToken = this.jwtService.sign(
      { email: user.email, sub: user._id },
      { expiresIn: '15m', secret: process.env.ACCESS_SECRET },
    );

    const refreshToken = this.jwtService.sign(
      { email: user.email, sub: user._id },
      { expiresIn: '7d', secret: process.env.REFRESH_SECRET },
    );

    user.refreshTokens = [...(user.refreshTokens || []), refreshToken];
    await user.save();

    res.cookie('refresh_token', refreshToken, {
      httpOnly: true,
      sameSite: 'lax',
      secure: false, // true in production (with HTTPS)
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    });

    return res.status(200).json({ accessToken });
  }

  async refresh(refreshToken: string, res: Response) {
    try {
      const payload = this.jwtService.verify(refreshToken, {
        secret: process.env.REFRESH_SECRET,
      });

      const user = await this.userService.findById(payload.sub);
      if (!user) throw new UnauthorizedException('User not found');

      const accessToken = this.jwtService.sign(
        { userId: user._id },
        { expiresIn: '15m', secret: process.env.ACCESS_SECRET },
      );

      return res.status(200).json({ accessToken });
    } catch (err) {
      throw new UnauthorizedException('Invalid refresh token');
    }
  }

  async logout(refreshToken: string, res: Response) {
    const payload = this.jwtService.decode(refreshToken) as any;
    const user = await this.userService.findByEmail(payload?.email);

    if (user) {
      user.refreshTokens = (user.refreshTokens || []).filter(
        (t) => t !== refreshToken,
      );
      await user.save();
    }

    res.clearCookie('refresh_token');
    return { message: 'Logged out' };
  }

  async googleLogin(email: string, oauthId: string, res: Response) {
    let user = await this.userService.findByEmail(email);

    if (user) {
      // Link if not already linked
      if (!user.oauthProvider) {
        user.oauthProvider = 'google';
        user.oauthId = oauthId;
        await user.save();
      }
    } else {
      // Create new user
      user = await this.userService.create({
        email,
        isEmailVerified: true,
        oauthProvider: 'google',
        oauthId,
      });
    }

    const accessToken = this.jwtService.sign(
      { email: user.email, sub: user._id },
      { expiresIn: '15m' },
    );

    const refreshToken = this.jwtService.sign(
      { email: user.email, sub: user._id },
      { expiresIn: '7d' },
    );

    user.refreshTokens = [...(user.refreshTokens || []), refreshToken];
    await user.save();

    res.cookie('refresh_token', refreshToken, {
      httpOnly: true,
      secure: true,
      sameSite: 'strict',
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    return { accessToken };
  }

  async forgotPassword(email: string) {
    const user = await this.userService.findByEmail(email);
    if (!user) throw new BadRequestException('User not found');

    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const otpExpiresAt = new Date(Date.now() + 5 * 60 * 1000); // 5 min validity

    user.otp = otp;
    user.otpExpiresAt = otpExpiresAt;
    await user.save();

    await this.sendOtpEmail(user.email, otp, 'reset');
    return { message: 'OTP sent to your email for password reset' };
  }

  async resetPassword(email: string, otp: string, newPassword: string) {
    const user = await this.userService.findByEmail(email);
    if (!user) throw new BadRequestException('User not found');

    const now = new Date();

    if (
      !user.otp ||
      user.otp !== otp ||
      !user.otpExpiresAt ||
      user.otpExpiresAt.getTime() < now.getTime()
    ) {
      throw new BadRequestException('Invalid or expired OTP');
    }

    user.password = await bcrypt.hash(newPassword, 10);
    user.otp = undefined;
    user.otpExpiresAt = undefined;

    await user.save();
    return { message: 'Password has been reset successfully' };
  }
}
