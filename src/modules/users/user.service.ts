import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { User } from './entities/user.entity.js';
import { Repository } from 'typeorm';
import { normalizeEmail } from '../../common/utils/email.util.js';
import { email } from 'zod';

export interface CreateUserInput {
  email: string;
  passwordHash: string | null;
  emailVerified?: boolean;
}

@Injectable()
export class UserService {
  constructor(
    @InjectRepository(User)
    private readonly users: Repository<User>,
  ) {}

  findByEmail(email: string): Promise<User | null> {
    return this.users.findOneBy({ email: normalizeEmail(email) });
  }

  findById(id: string): Promise<User | null> {
    return this.users.findOneBy({ id });
  }

  async create(input: CreateUserInput): Promise<User> {
    const user = this.users.create({
      email: normalizeEmail(input.email),
      passwordHash: input.passwordHash,
      emailVerified: input.emailVerified ?? false,
      emailVerifiedAt: input.emailVerified ? new Date() : null,
    });

    return this.users.save(user);
  }
}
