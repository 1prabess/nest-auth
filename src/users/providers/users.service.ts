import {
  BadRequestException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { Repository } from 'typeorm';
import { User } from '../user.entity';
import { InjectRepository } from '@nestjs/typeorm';
import { CreateUserDto } from '../dtos/create-user.dto';
import bcrypt from 'bcryptjs';
import { UserRole } from '../enums/user-role.enum';

@Injectable()
export class UsersService {
  constructor(
    @InjectRepository(User)
    private readonly usersRepository: Repository<User>,
  ) {}

  async create(createUserDto: CreateUserDto) {
    // Check if the user already exists
    const existingUser = await this.usersRepository.findOneBy({
      email: createUserDto.email,
    });

    if (existingUser) {
      throw new BadRequestException('User already exists');
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(createUserDto.password, 10);

    // Create user
    const user = this.usersRepository.create({
      email: createUserDto.email,
      password: hashedPassword,
      role: UserRole.USER,
    });

    // Save user
    const savedUser = await this.usersRepository.save(user);

    // Extract and return safe user (without password)
    const { password, ...safeUser } = savedUser;
    return safeUser;
  }

  async findByEmail(email: string) {
    return this.usersRepository.findOneBy({ email });
  }

  async findById(id: number) {
    // Fetch user
    const user = await this.usersRepository.findOne({ where: { id } });

    if (!user) {
      throw new NotFoundException('User not found');
    }

    // Extract and return safe user (without password)
    const { password, ...safeUser } = user;
    return safeUser;
  }

  async findAll() {
    // Fetch all users
    const users = await this.usersRepository.find();

    // Extract and return safe users (without password)
    return users.map(({ password, ...safeUser }) => safeUser);
  }
}
