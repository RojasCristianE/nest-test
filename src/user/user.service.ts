import { Injectable } from "@nestjs/common";
import { PrismaService } from "../prisma/prisma.service";

@Injectable()
export class UserService {
    constructor( private prisma: PrismaService ) {}

    async getAllUsers() {
        const
            select = { 
                id: true,
                email: true,
                firstName: true,
                lastName: true
            },
            users = await this.prisma.user.findMany({ select });
        
        return { users };
    }

    async getUserInfo( user: object ) {
        return user
    }
}