import { Body, Controller, Post, UnauthorizedException } from '@nestjs/common';
import { AuthService } from './auth.service';
import { JwtAuthGuard } from './jwt-auth.guard';
import { UseGuards, Get, Req, Res } from '@nestjs/common';
import { Request, Response } from 'express';
import { AuthGuard } from '@nestjs/passport';

@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  @Post('signup')
  async signup(
    @Body()
    body: {
      email: string;
      password: string;
      name: string;
      dob: string;
    },
  ) {
    return this.authService.signup(
      body.email,
      body.password,
      body.name,
      body.dob,
    );
  }

  @Post('verify-otp')
  verifyOtp(@Body() body: { email: string; otp: string }) {
    return this.authService.verifyOtp(body.email, body.otp);
  }

  @Post('resend-otp')
  resendOtp(@Body() body: { email: string }) {
    return this.authService.resendOtp(body.email);
  }

  @Post('send-otp-login')
  sendOtpLogin(@Body() body: { email: string }) {
    return this.authService.sendOtpForLogin(body.email);
  }

  @Post('verify-otp-login')
  async verifyOtpLogin(
    @Body() body: { email: string; otp: string },
    @Res() res: Response,
  ) {
    const result = await this.authService.verifyOtpForLogin(
      body.email,
      body.otp,
      res,
    );
    return res.status(200).json(result);
  }

  @Post('login')
  async login(
    @Body() body: { email: string; password: string },
    @Res() res: Response,
  ) {
    const result = await this.authService.login(body.email, body.password, res);
    return res.status(200).json(result);
  }

  @Post('refresh')
  refresh(@Req() req: Request, @Res() res: Response) {
    const refreshToken = req.cookies?.refresh_token; // ⬅️ MUST come from cookie
    if (!refreshToken) {
      throw new UnauthorizedException('No refresh token provided');
    }
    return this.authService.refresh(refreshToken, res);
  }

  @Post('logout')
  logout(@Req() req: Request, @Res() res: Response) {
    const token = req.cookies['refresh_token'];
    return this.authService.logout(token, res);
  }

  @Get('protected')
  @UseGuards(JwtAuthGuard)
  getProtected(@Req() req) {
    return { message: `Hello, ${req.user.email}` };
  }

  @Get('google')
  @UseGuards(AuthGuard('google'))
  async googleAuth() {
    // Redirect handled by Passport
  }

  @Get('google/callback')
  @UseGuards(AuthGuard('google'))
  async googleCallback(@Req() req, @Res() res: Response) {
    const { email, oauthId } = req.user;
    const result = await this.authService.googleLogin(email, oauthId, res);
    return res.json(result);
  }

  @Post('forgot-password')
  forgotPassword(@Body() body: { email: string }) {
    return this.authService.forgotPassword(body.email);
  }

  @Post('reset-password')
  resetPassword(
    @Body() body: { email: string; otp: string; newPassword: string },
  ) {
    return this.authService.resetPassword(
      body.email,
      body.otp,
      body.newPassword,
    );
  }
}

@Controller('protected')
export class ProtectedController {
  @UseGuards(JwtAuthGuard)
  @Get()
  getProtected(@Req() req) {
    return { message: `You are logged in as ${req.user.email}` };
  }
}
