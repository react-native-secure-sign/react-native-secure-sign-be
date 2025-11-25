import {
  BadRequestException,
  Injectable,
  InternalServerErrorException,
  Logger,
  UnauthorizedException,
} from '@nestjs/common';
import { randomBytes } from 'crypto';
import canonicalize from 'canonicalize';
import { InitiateRegisterDto } from './dto/initiate.dto';
import { verifySignature } from './utils/crypto';

type ChallengeRecord = {
  informationToSignBytes: Buffer;
  exp: number;
  used: boolean;
};

export type DeviceInfo = {
  platform?: string;
  appVersion?: string;
};

type InitiateChallengeParams = {
  method: string;
  path: string;
  body?: InitiateRegisterDto;
};

type FinishChallengeParams = {
  challengeId: string;
  signature: string;
  publicKey: string;
};

type InitiateChallengeResult = {
  informationToSign_b64u: string;
  challengeId: string;
};

type FinishChallengeResult = {
  success: true;
};

@Injectable()
export class RegisterService {
  private readonly logger = new Logger(RegisterService.name);

  private readonly store = new Map<string, ChallengeRecord>();
  private readonly VER = 'SS1';
  private readonly ALG = 'ES256';
  private readonly SIG_FORMAT = 'P1363';
  private readonly AUD = 'https://secure-sign.com/api';
  private readonly TTL_MS = 5 * 60 * 1000;

  private generateId(bytes = 32): string {
    return randomBytes(bytes).toString('base64url');
  }

  initiateChallenge(params: InitiateChallengeParams): InitiateChallengeResult {
    const { method, path, body } = params;

    if (!method || !path) {
      throw new BadRequestException('Missing method or path');
    }

    const now = Date.now();
    const exp = now + this.TTL_MS;
    const nonce = this.generateId(32);
    const challengeId = this.generateId(32);
    const platform = body?.device?.platform;
    const appVersion = body?.device?.appVersion;

    const challengeObj: Record<string, unknown> = {
      ver: this.VER,
      alg: this.ALG,
      sigFormat: this.SIG_FORMAT,
      aud: this.AUD,
      nonce,
      ts: now,
      exp,
      method: method.toUpperCase(),
      path,
      challengeId,
    };

    if (platform) {
      challengeObj.platform = platform;
    }
    if (appVersion) {
      challengeObj.appVersion = appVersion;
    }

    const informationToSign = canonicalize(challengeObj);
    if (!informationToSign) {
      this.logger.error('Failed to canonicalize challenge object', {
        challengeObj,
      });
      throw new InternalServerErrorException(
        'Failed to canonicalize challenge object',
      );
    }

    const informationToSignBytes = Buffer.from(informationToSign, 'utf-8');
    const informationToSign_b64u = informationToSignBytes.toString('base64url');

    this.logger.debug('Created challenge', {
      challengeId,
      nonce,
      exp,
      method: method.toUpperCase(),
      path,
      platform,
    });

    this.store.set(challengeId, {
      informationToSignBytes,
      exp,
      used: false,
    });

    return { informationToSign_b64u, challengeId };
  }

  finishChallenge(params: FinishChallengeParams): FinishChallengeResult {
    const { challengeId, signature, publicKey } = params;

    if (!challengeId || !signature || !publicKey) {
      throw new BadRequestException(
        'Missing challengeId, signature or publicKey',
      );
    }

    this.logger.debug('finishChallenge called', { challengeId });

    const challenge = this.store.get(challengeId);

    if (!challenge) {
      this.logger.warn('Challenge not found', { challengeId });
      throw new BadRequestException('Challenge not found');
    }

    const now = Date.now();

    if (challenge.exp < now) {
      this.logger.warn('Challenge expired', {
        challengeId,
        exp: challenge.exp,
      });
      this.store.delete(challengeId);
      throw new UnauthorizedException('Challenge expired');
    }

    if (challenge.used) {
      this.logger.warn('Challenge already used', { challengeId });
      this.store.delete(challengeId);
      throw new UnauthorizedException('Challenge already used');
    }

    const isValid = verifySignature({
      publicKeyB64u: publicKey,
      signatureB64u: signature,
      data: challenge.informationToSignBytes,
    });

    if (!isValid) {
      this.logger.warn('Invalid signature', { challengeId });
      throw new UnauthorizedException('Invalid signature');
    }

    challenge.used = true;
    this.logger.log('Challenge successfully verified', { challengeId });
    return { success: true };
  }
}
