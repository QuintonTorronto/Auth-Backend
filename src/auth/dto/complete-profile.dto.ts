import { IsString, IsDateString } from 'class-validator';

export class CompleteProfileDto {
  @IsString()
  name: string;

  @IsDateString()
  dob: string; // Will be converted to Date in the service
}
