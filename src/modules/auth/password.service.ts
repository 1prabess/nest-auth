import { Injectable } from '@nestjs/common';
import { argon2id, hash, verify } from 'argon2';

const ARGON2_OPTIONS = {
  type: argon2id,
  memoryCost: 19456,
  timeCost: 2,
  parallelism: 1,
} as const;

@Injectable()
export class PasswordService {
  async hashPassword(plainText: string): Promise<string> {
    return hash(plainText, ARGON2_OPTIONS);
  }

  async verifyPassword(digest: string, plainText: string): Promise<boolean> {
    try {
      return verify(digest, plainText);
    } catch {
      return false;
    }
  }
}
