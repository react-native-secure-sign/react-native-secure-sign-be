import {
  Body,
  Controller,
  HttpCode,
  Post,
  Req,
  ValidationPipe,
} from '@nestjs/common';
import type { Request } from 'express';
import { RegisterService } from './register.service';
import { InitiateRegisterDto } from './dto/initiate.dto';
import { FinishRegisterDto } from './dto/finish.dto';

@Controller('v1/register')
export class RegisterController {
  constructor(private readonly registerService: RegisterService) {}

  @Post('initiate-challenge')
  @HttpCode(200)
  initiate(
    @Req() req: Request,
    @Body(new ValidationPipe()) body: InitiateRegisterDto,
  ) {
    return this.registerService.initiateChallenge({
      method: req.method,
      path: req.path,
      body,
    });
  }

  @Post('finish-challenge')
  @HttpCode(200)
  finish(@Body(new ValidationPipe()) body: FinishRegisterDto) {
    return this.registerService.finishChallenge(body);
  }
}
