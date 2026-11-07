import { UserResponseDto } from './dto/user-response.dto.js';
import { User } from './entities/user.entity.js';

export const toUserResponse = (user: User): UserResponseDto => {
  return {
    id: user.id,
    email: user.email,
    emailVerified: user.emailVerified,
    createdAt: user.createdAt,
  };
};
