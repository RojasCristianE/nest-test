import { Controller, Get, HttpCode, HttpStatus, UseGuards } from '@nestjs/common';
import { UserService } from './user.service';
import { User } from '@prisma/client';
import { GetUser } from '../auth/decorator';
import { JwtGuard } from '../auth/guard';

@UseGuards(JwtGuard)
@Controller('users')
export class UserController {
    constructor( private userService: UserService ) {}

    @Get()
    getAllUsers() {
        return this.userService.getAllUsers();
    }

    @HttpCode(HttpStatus.OK)
    @Get("me")
    getMe(@GetUser() user: User) {
        return this.userService.getUserInfo(user);
    }
}
