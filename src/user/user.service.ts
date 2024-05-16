import { Injectable, NotFoundException } from '@nestjs/common';
import { GetUserDto } from './dto/user.dto';
import { PrismaClient } from '@prisma/client';

@Injectable()
export class UserService {
    private prisma = new PrismaClient()


    async getUser(getUserDto: GetUserDto): Promise<object> {
        const user = await this.prisma.user.findUnique({
            where: {
                id: getUserDto.id
            },
            select:{
                id: true,
                fullName: true,
                email: true,
                role: true,
                emailConfirmed: true
            }
        })

        if (!user) throw new NotFoundException('user not found')

        return user
    }

    
}
