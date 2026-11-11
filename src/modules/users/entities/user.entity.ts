import {
  Column,
  CreateDateColumn,
  Entity,
  OneToMany,
  PrimaryGeneratedColumn,
  UpdateDateColumn,
  type Relation,
} from 'typeorm';
import { OauthAccount } from './oauth-account.entity.js';
import { RefreshToken } from '../../auth/entities/refresh-token.entity.js';

@Entity()
export class User {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({
    type: 'varchar',
    length: 320,
  })
  email: string;

  @Column({
    type: 'varchar',
    nullable: true,
    name: 'password_hash',
  })
  passwordHash: string | null;

  @Column({
    type: 'boolean',
    default: false,
    name: 'email_verified',
  })
  emailVerified: boolean;

  @Column({
    type: 'timestamptz',
    nullable: true,
    name: 'email_verified_at',
  })
  emailVerifiedAt: Date | null;

  @CreateDateColumn({
    type: 'timestamptz',
    name: 'created_at',
  })
  createdAt: Date;

  @UpdateDateColumn({
    type: 'timestamptz',
    name: 'updated_at',
  })
  updatedAt: Date;

  @OneToMany(() => OauthAccount, (oauthAccount) => oauthAccount.user)
  oauthAccounts: OauthAccount[];

  @OneToMany(() => RefreshToken, (refreshToken) => refreshToken.user)
  refreshTokens: Relation<RefreshToken[]>;
}
