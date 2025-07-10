import {
  Body,
  Controller,
  Post,
  UnauthorizedException,
  UseGuards,
  Get,
  Req,
  Res,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { JwtAuthGuard } from './jwt-auth.guard';
import { Request, Response } from 'express';
import { AuthGuard } from '@nestjs/passport';
import { CompleteProfileDto } from './dto/complete-profile.dto';

@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  @Post('signup')
  signup(
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
    return this.authService.sendOtpLogin(body.email); // ✅ updated to match new name
  }

  @Post('verify-otp-login')
  async verifyOtpLogin(
    @Body() body: { email: string; otp: string },
    @Res() res: Response,
  ) {
    return this.authService.verifyOtpLogin(body.email, body.otp, res); // ✅ name aligned
  }

  @Post('login')
  async login(
    @Body() body: { email: string; password: string },
    @Res({ passthrough: true }) res: Response,
  ) {
    const { accessToken, refreshToken } = await this.authService.login(
      body.email,
      body.password,
    );
    res.cookie('refresh_token', refreshToken, {
      httpOnly: true,
      sameSite: 'lax',
      secure: false,
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });
    return { accessToken };
  }

  @Post('refresh')
  refresh(@Req() req: Request, @Res() res: Response) {
    const refreshToken = req.cookies?.refresh_token;
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

  @Post('google/token')
  googleLoginWithToken(
    @Body('credential') credential: string,
    @Res() res: Response,
  ) {
    return this.authService.googleLoginWithCredential(credential, res);
  }

  @Get('google/callback')
  @UseGuards(AuthGuard('google'))
  async googleCallback(@Req() req, @Res() res: Response) {
    const { email, oauthId } = req.user;
    const result = await this.authService.googleLoginCallback(
      email,
      oauthId,
      res,
    );
    return res.json(result);
  }

  @UseGuards(JwtAuthGuard)
  @Get('me')
  getProfile(@Req() req) {
    return req.user;
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

  @UseGuards(JwtAuthGuard)
  @Post('complete-profile')
  async completeProfile(@Req() req, @Body() body: CompleteProfileDto) {
    return this.authService.completeProfile(
      req.user.email,
      body.name,
      body.dob,
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
