import {
  Column,
  CreateDateColumn,
  Entity,
  JoinColumn,
  ManyToOne,
  PrimaryGeneratedColumn,
} from 'typeorm';
import type { User } from './user.entity.js';

@Entity()
export class OauthAccount {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({
    type: 'varchar',
    length: 32,
  })
  provider: string;

  @Column({
    name: 'provider_account_id',
    type: 'varchar',
    length: 255,
  })
  providerAccountId: string;

  @CreateDateColumn({
    name: 'created_at',
    type: 'timestamptz',
  })
  createdAt: Date;

  @Column({ name: 'user_id', type: 'uuid' })
  userId: string;

  @ManyToOne('User', 'oauthAccounts', { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'user_id' })
  user: User;
}
