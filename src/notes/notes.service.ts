import {
  Injectable,
  NotFoundException,
  ForbiddenException,
} from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model, Types } from 'mongoose';
import { Note, NoteDocument } from './schemas/note.schema';
import { CreateNoteDto } from './dto/create-note.dto';
import { UpdateNoteDto } from './dto/update-note.dto';

@Injectable()
export class NotesService {
  constructor(@InjectModel(Note.name) private noteModel: Model<NoteDocument>) {}

  async create(userId: string, createNoteDto: CreateNoteDto) {
    return this.noteModel.create({
      content: createNoteDto.content,
      user: userId,
    });
  }

  async findAllByUser(userId: string) {
    return this.noteModel.find({ user: userId }).sort({ updatedAt: -1 });
  }

  async update(userId: string, noteId: string, updateDto: UpdateNoteDto) {
    const note = await this.noteModel.findById(noteId);
    if (!note) throw new NotFoundException('Note not found');
    if (note.user.toString() !== userId) throw new ForbiddenException();

    Object.assign(note, updateDto);
    return note.save();
  }

  async remove(userId: string, noteId: string) {
    const note = await this.noteModel.findById(noteId);
    if (!note) throw new NotFoundException('Note not found');
    if (note.user.toString() !== userId) throw new ForbiddenException();

    await this.noteModel.deleteOne({ _id: noteId });
    return { message: 'Note deleted' };
  }
}
