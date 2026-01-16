import { Injectable } from '@nestjs/common';
import { Repository } from 'typeorm';
import { Session } from '../session.entity';
import { InjectRepository } from '@nestjs/typeorm';

@Injectable()
export class SessionsService {
  constructor(
    @InjectRepository(Session)
    private sessionsRepository: Repository<Session>,
  ) {}

  // Create session
  async create(userId: number, userAgent?: string, expiresIn = 30) {
    // Set session expiry
    const expiresAt = new Date(Date.now() + expiresIn * 24 * 60 * 60 * 1000);

    // Create session
    const session = this.sessionsRepository.create({
      user: { id: userId },
      userAgent,
      expiresAt,
    });

    return this.sessionsRepository.save(session);
  }

  // Find session by id
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

  async delete(sessionId: number) {
    return await this.sessionsRepository.delete(sessionId);
  }
}
