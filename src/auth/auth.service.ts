import {
  Injectable,
  BadRequestException,
  UnauthorizedException,
} from '@nestjs/common';
import { UserService } from 'src/user/user.service';
import * as bcrypt from 'bcrypt';
import * as nodemailer from 'nodemailer';
import { JwtService } from '@nestjs/jwt';
import { Response } from 'express';
import { OAuth2Client } from 'google-auth-library';
import { InjectModel } from '@nestjs/mongoose';
import { User } from 'src/user/schemas/user.schema';
import { Model } from 'mongoose';

@Injectable()
export class AuthService {
  private googleClient: OAuth2Client;

  constructor(
    @InjectModel(User.name) private userModel: Model<User>,
    private userService: UserService,
    private jwtService: JwtService,
  ) {
    const googleClientId = process.env.GOOGLE_CLIENT_ID;
    if (!googleClientId) throw new Error('GOOGLE_CLIENT_ID not defined');
    this.googleClient = new OAuth2Client(googleClientId);
  }

  private async generateTokens(user: User) {
    const accessToken = this.jwtService.sign(
      { email: user.email, sub: user._id },
      { expiresIn: '15m', secret: process.env.ACCESS_SECRET },
    );

    const refreshToken = this.jwtService.sign(
      { email: user.email, sub: user._id },
      { expiresIn: '7d', secret: process.env.REFRESH_SECRET },
    );

    user.refreshTokens = [...(user.refreshTokens || []), refreshToken];

    await user.save({ validateBeforeSave: false }); //skiping validation for google login profiles.

    return { accessToken, refreshToken };
  }

  private setAuthCookies(res: Response, refreshToken: string) {
    res.cookie('refresh_token', refreshToken, {
      httpOnly: true,
      sameSite: 'lax',
      secure: false,
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });
  }

  async signup(email: string, password: string, name: string, dob: string) {
    const existing = await this.userService.findByEmail(email);
    if (existing) throw new BadRequestException('Email already exists');
    const hash = await bcrypt.hash(password, 10);
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const user = await this.userService.create({
      name,
      email,
      password: hash,
      dob: new Date(dob),
      otp,
      otpExpiresAt: new Date(Date.now() + 5 * 60 * 1000),
    });
    await this.sendOtpEmail(email, otp, 'signup');
    return { message: 'OTP sent to email' };
  }

  async login(email: string, password: string) {
    const user = await this.userService.findByEmail(email);
    if (
      !user ||
      !user.password ||
      !(await bcrypt.compare(password, user.password))
    ) {
      throw new BadRequestException('Invalid credentials');
    }
    if (!user.isEmailVerified) {
      throw new BadRequestException('Email not verified');
    }

    const { accessToken, refreshToken } = await this.generateTokens(user);
    return { accessToken, refreshToken };
  }
  async sendOtpEmail(
    to: string,
    otp: string,
    context: 'signup' | 'reset' | 'login',
  ) {
    const { EMAIL_USER, EMAIL_PASS } = process.env;
    if (!EMAIL_USER || !EMAIL_PASS) throw new Error('Missing email creds');

    const subjects = {
      signup: 'Email Verification Code',
      reset: 'Password Reset Code',
      login: 'Login OTP Code',
    };

    const texts = {
      signup: `Verification code: ${otp}. Expires in 5 minutes.`,
      reset: `Reset code: ${otp}. Expires in 5 minutes.`,
      login: `Login OTP: ${otp}. Expires in 5 minutes.`,
    };

    const transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: { user: EMAIL_USER, pass: EMAIL_PASS },
    });

    await transporter.sendMail({
      from: `"NoReply" <${EMAIL_USER}>`,
      to,
      subject: subjects[context],
      text: texts[context],
    });
  }

  async verifyOtp(email: string, otp: string) {
    const user = await this.userService.findByEmail(email);
    if (
      !user ||
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
    return { message: 'Email verified' };
  }

  async resendOtp(email: string) {
    const user = await this.userService.findByEmail(email);
    if (!user) throw new BadRequestException('User not found');
    if (user.isEmailVerified) throw new BadRequestException('Already verified');

    const now = Date.now();
    if (user.lastOtpSentAt && now - user.lastOtpSentAt.getTime() < 120000)
      throw new BadRequestException('Wait before requesting another OTP');

    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    user.otp = otp;
    user.otpExpiresAt = new Date(now + 5 * 60 * 1000);
    user.lastOtpSentAt = new Date(now);
    await user.save();
    await this.sendOtpEmail(user.email, otp, 'signup');
    return { message: 'OTP resent' };
  }

  async sendOtpLogin(email: string) {
    const user = await this.userService.findByEmail(email);
    if (!user) throw new BadRequestException('User not found');

    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    user.otp = otp;
    user.otpExpiresAt = new Date(Date.now() + 5 * 60 * 1000);
    await user.save();
    await this.sendOtpEmail(email, otp, 'login');
    return { message: 'Login OTP sent' };
  }

  async verifyOtpLogin(email: string, otp: string, res: Response) {
    const user = await this.userService.findByEmail(email);

    const isOtpInvalid =
      !user ||
      user.otp !== otp ||
      !user.otpExpiresAt ||
      user.otpExpiresAt.getTime() < Date.now();

    if (isOtpInvalid) {
      throw new BadRequestException('Invalid or expired OTP');
    }

    user.isEmailVerified = true;
    user.otp = undefined;
    user.otpExpiresAt = undefined;
    await user.save();

    const { accessToken, refreshToken } = await this.generateTokens(user);
    this.setAuthCookies(res, refreshToken); // sets refresh token cookie
    return { accessToken };
  }

  async forgotPassword(email: string) {
    const user = await this.userService.findByEmail(email);
    if (!user) throw new BadRequestException('User not found');

    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    user.otp = otp;
    user.otpExpiresAt = new Date(Date.now() + 5 * 60 * 1000);
    await user.save();
    await this.sendOtpEmail(email, otp, 'reset');
    return { message: 'Password reset OTP sent' };
  }

  async resetPassword(email: string, otp: string, newPassword: string) {
    const user = await this.userService.findByEmail(email);
    if (
      !user ||
      user.otp !== otp ||
      !user.otpExpiresAt ||
      user.otpExpiresAt.getTime() < Date.now()
    ) {
      throw new BadRequestException('Invalid or expired OTP');
    }

    user.password = await bcrypt.hash(newPassword, 10);
    user.otp = undefined;
    user.otpExpiresAt = undefined;
    await user.save();
    return { message: 'Password reset successful' };
  }

  async googleLoginCallback(email: string, oauthId: string, res: Response) {
    let user = await this.userService.findByEmail(email);
    if (!user) {
      user = await this.userService.create({
        email,
        oauthProvider: 'google',
        oauthId,
        isEmailVerified: true,
      });
    }
    const { accessToken, refreshToken } = await this.generateTokens(user);
    this.setAuthCookies(res, refreshToken);
    return { accessToken };
  }

  async googleLoginWithCredential(credential: string, res: Response) {
    const ticket = await this.googleClient.verifyIdToken({
      idToken: credential,
      audience: process.env.GOOGLE_CLIENT_ID,
    });

    const payload = ticket.getPayload();
    if (!payload || !payload.email) {
      throw new UnauthorizedException('Invalid Google token');
    }

    const { email, name, sub: oauthId } = payload;
    let user = await this.userService.findByEmail(email);
    let requiresProfileCompletion = false;

    if (!user) {
      user = new this.userModel({
        email,
        oauthId,
        name: name || null,
        oauthProvider: 'google',
        isEmailVerified: true,
      });

      requiresProfileCompletion = true;

      await user.save({ validateBeforeSave: false });
    }

    if (!user.dob) {
      requiresProfileCompletion = true;
    }

    const { accessToken, refreshToken } = await this.generateTokens(user);
    this.setAuthCookies(res, refreshToken);

    return res.status(200).json({ accessToken, requiresProfileCompletion });
  }

  async completeProfile(email: string, name: string, dob: string) {
    const user = await this.userService.findByEmail(email);
    if (!user) {
      throw new BadRequestException('User not found');
    }

    if (user.dob && user.name) {
      return { message: 'Profile is already complete' };
    }

    user.name = name;
    user.dob = new Date(dob);
    await user.save();

    return { message: 'Profile updated successfully' };
  }

  async getUserById(id: string) {
    return this.userService.findById(id);
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
    return res.status(200).json({ message: 'Logged out' });
  }

  async refresh(refreshToken: string, res: Response) {
    try {
      const payload = this.jwtService.verify(refreshToken, {
        secret: process.env.REFRESH_SECRET,
      });

      const user = await this.userService.findById(payload.sub);
      if (!user) throw new UnauthorizedException('User not found');

      const accessToken = this.jwtService.sign(
        { email: user.email, sub: user._id },
        { expiresIn: '15m', secret: process.env.ACCESS_SECRET },
      );

      const requiresProfileCompletion = !user.name || !user.dob;

      return res.status(200).json({ accessToken, requiresProfileCompletion });
    } catch {
      throw new UnauthorizedException('Invalid refresh token');
    }
  }
}
