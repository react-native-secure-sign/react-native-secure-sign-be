import { IsNotEmpty, IsString } from 'class-validator';

export class FinishRegisterDto {
  @IsString()
  @IsNotEmpty()
  challengeId: string;

  @IsString()
  @IsNotEmpty()
  signature: string;

  @IsString()
  @IsNotEmpty()
  publicKey: string;
}
