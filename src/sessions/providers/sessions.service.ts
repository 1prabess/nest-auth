import { Injectable } from '@nestjs/common';
import { Repository } from 'typeorm';
import { Session } from '../session.entity';
import { InjectRepository } from '@nestjs/typeorm';
import { User } from 'src/users/user.entity';

@Injectable()
export class SessionsService {
  constructor(
    @InjectRepository(Session)
    private sessionsRepository: Repository<Session>,
  ) {}

  async create(userId: number, userAgent?: string, expiresIn = 30) {
    const expiresAt = new Date(Date.now() + expiresIn * 24 * 60 * 60 * 1000);

    const session = this.sessionsRepository.create({
      user: { id: userId },
      userAgent,
      expiresAt,
    });

    return this.sessionsRepository.save(session);
  }

  async findById(sessionId: number) {
    return await this.sessionsRepository.findOne({
      where: {
        id: sessionId,
      },
      relations: {
        user: true,
      },
    });
  }

  // Extend a session expiration by given days
  async extendSession(sessionId: number, extraDays = 30) {
    const session = await this.findById(sessionId);
    if (!session) return null;

    session.expiresAt = new Date(Date.now() + extraDays * 24 * 60 * 60 * 1000);
    return this.sessionsRepository.save(session);
  }
}
