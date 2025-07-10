import { Injectable } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { User, UserDocument } from './schemas/user.schema';
import { Model } from 'mongoose';

@Injectable()
export class UserService {
  constructor(@InjectModel(User.name) private userModel: Model<UserDocument>) {}

  async findByEmail(email: string) {
    return this.userModel.findOne({ email });
  }

  async create(data: Partial<UserDocument>) {
    const user = new this.userModel(data);
    return user.save();
  }

  async findById(id: string) {
    return this.userModel.findById(id);
  }
}
