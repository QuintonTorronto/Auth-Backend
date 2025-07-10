import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document } from 'mongoose';

export type UserDocument = User & Document;

@Schema()
export class User {
  @Prop({ required: true })
  name: string;

  @Prop({ required: true, unique: true })
  email: string;

  @Prop({ required: true })
  dob: Date;

  @Prop()
  password?: string;

  @Prop()
  isEmailVerified: boolean;

  @Prop()
  otp?: string;

  @Prop()
  otpExpiresAt?: Date;

  @Prop()
  oauthProvider?: string;

  @Prop()
  oauthId?: string;

  @Prop({ type: [String] })
  refreshTokens?: string[];

  @Prop()
  lastOtpSentAt?: Date;
}

export const UserSchema = SchemaFactory.createForClass(User);
