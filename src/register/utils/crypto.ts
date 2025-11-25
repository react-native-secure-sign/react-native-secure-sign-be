import { BadRequestException } from '@nestjs/common';
import { createPublicKey, createVerify, KeyObject } from 'crypto';

export function verifySignature(params: {
  publicKeyB64u: string;
  signatureB64u: string;
  data: Buffer;
}): boolean {
  const { publicKeyB64u, signatureB64u, data } = params;

  let key: KeyObject;
  try {
    key = createPublicKey({
      key: Buffer.from(publicKeyB64u, 'base64url'),
      format: 'der',
      type: 'spki',
    });
  } catch {
    throw new BadRequestException('Invalid public key');
  }

  const verifier = createVerify('sha256');
  verifier.update(data);
  verifier.end();

  try {
    return verifier.verify(
      { key, dsaEncoding: 'ieee-p1363' },
      Buffer.from(signatureB64u, 'base64url'),
    );
  } catch {
    throw new BadRequestException('Invalid signature format');
  }
}
