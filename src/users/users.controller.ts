import { Controller, Get, Req, UseGuards } from '@nestjs/common';
import { UsersService } from './providers/users.service';
import { ApiOperation, ApiTags } from '@nestjs/swagger';
import { ResponseMessage } from 'src/common/decorators/response-message.decorator';
import { JwtAuthGuard } from 'src/guards/jwt-auth.guard';
import { RoleGuard } from 'src/guards/role.guard';
import { Roles } from 'src/common/decorators/roles.decorator';
import { UserRole } from './enums/user-role.enum';
import type { AuthenticatedRequest } from 'src/common/types/express-request.interface';

@ApiTags('Users')
@Controller('users')
@UseGuards(JwtAuthGuard, RoleGuard)
export class UsersController {
  constructor(private readonly usersService: UsersService) {}

  // Fetch all users
  @ApiOperation({
    summary: 'Fetches all users (Admin only)',
    description: 'Requires ADMIN role. Returns a list of all registered users.',
  })
  @Get()
  @Roles([UserRole.ADMIN])
  @ResponseMessage('Users fetched successfully')
  findAll() {
    return this.usersService.findAll();
  }

  // Fetch authenticated user's profile
  @ApiOperation({
    summary: 'Fetch the authenticated user profile',
    description: 'Returns the profile of the currently logged-in user.',
  })
  @Get('me')
  @ResponseMessage('User profile fetched successfully')
  findMe(@Req() request: AuthenticatedRequest) {
    return this.usersService.findById(request.userId);
  }
}
