import { BadRequestException, Injectable, NotFoundException } from '@nestjs/common';
import { ChangePasswordDto, ForgotPasswordDto, GenerateAuthTokensDto, LoginDto, RefreshDto, RegisterDto, SendConfirmEmailDto, VerifyEmailDto } from './dto/auth.dto';
import { PrismaClient, TOKEN_TYPE } from '@prisma/client';
import * as bcrypt from 'bcrypt';
import { generateRandomAlphanumeric } from 'src/utils/random.util';
import { MailService, MailTemplate } from 'src/mail/mail.service';
import * as jwt from 'jsonwebtoken';
import { UserService } from 'src/user/user.service';

@Injectable()
export class AuthService {
    private prisma = new PrismaClient()
    private saltRounds = 8
    private readonly secretKey = process.env.JWT_ACCESS_TOKEN_SECRET;
    
    constructor(private readonly mailService: MailService, private readonly userService: UserService) { }

    async register(registerDto: RegisterDto): Promise<any> {

        let oldUser = await this.prisma.user.findUnique({
            where: {
                email: registerDto.email
            }
        })

        if (oldUser) throw new BadRequestException('email already registered')

        if (registerDto.confirmPassword !== registerDto.password) throw new BadRequestException('password doesnt match confirmPassword')

        const { password, confirmPassword, ...data } = registerDto;
        const hash = await bcrypt.hash(registerDto.password, this.saltRounds);

        const user = await this.prisma.user.create({
            data: {
                ...data,
                password: hash,
            },
        });

        this.requestEmailVerification({ email: user.email })

        return { message: 'registration successfull, check your email for verification instructions!' };
    }

    async requestEmailVerification(sendConfirmEmailDto: SendConfirmEmailDto) {

        let user = await this.prisma.user.findUnique({
            where: {
                email: sendConfirmEmailDto.email
            }
        })
        if (!user) throw new BadRequestException('user with email not found')

        if (user.emailConfirmed) throw new BadRequestException('email is already verified')


        const oldToken = await this.prisma.token.findFirst({
            where: {
                type: TOKEN_TYPE.confirm_token,
                user_id: user.id,
            }
        })
        if (oldToken) await this.prisma.token.delete({ where: { id: oldToken.id } })

        const otp = await generateRandomAlphanumeric(52)

        const hash = await bcrypt.hash(otp, this.saltRounds)

        const expirationTime = new Date();
        expirationTime.setHours(expirationTime.getHours() + 1);
        const link = `${process.env.API_URL}/v1/auth/verify/${otp}`

        await this.prisma.token.create({
            data: {
                user_id: user.id,
                type: TOKEN_TYPE.confirm_token,
                token: hash,
                expire_at: expirationTime,

            }
        })

        await this.mailService.sendTemplate<{ link: string }>(
            MailTemplate.emailVerify,
            'Verify  your email address',
            { email: user.email },
            { link }
        )

        // sends template

        return { message: "confirmation email sent" }
    }

    async forgotPassword(forgotPasswordDto: ForgotPasswordDto) {

        let user = await this.prisma.user.findUnique({
            where: {
                email: forgotPasswordDto.email
            }
        })

        if (!user) throw new NotFoundException('account not found')

        const oldToken = await this.prisma.token.findFirst({
            where: {
                type: TOKEN_TYPE.reset_token,
                user_id: user.id,
            }
        })
        if (oldToken) await this.prisma.token.delete({ where: { id: oldToken.id } })

        const otp = await generateRandomAlphanumeric(52)



        const expirationTime = new Date();
        expirationTime.setHours(expirationTime.getMinutes() + 30);

        const link = `${process.env.CLIENT_URL}/change-password/${otp}`

        await this.prisma.token.create({
            data: {
                user_id: user.id,
                type: TOKEN_TYPE.reset_token,
                token: otp,
                expire_at: expirationTime
            }
        })

        await this.mailService.sendTemplate<{ link: string }>(
            MailTemplate.forgotPassword,
            'password reset',
            { email: user.email },
            { link }
        )

        // sends template

        return { message: "recovery instructions sent to your mail" }
    }

    async changePassword(changePasswordDto: ChangePasswordDto) {
        // Check if token exists
        const token = await this.prisma.token.findFirst({
            where: {
                token: changePasswordDto.token,
                type: TOKEN_TYPE.reset_token
            }
        });

        if (!token) throw new NotFoundException('invalid reset token')
        const currentDateTime = new Date();

        // Check if the reset link is still valid
        if (token.expire_at <= currentDateTime) {
            await this.prisma.token.delete({
                where: {
                    id: token.id
                }
            });
            throw new BadRequestException('token has expired')
        }

        if (changePasswordDto.confirmPassword !== changePasswordDto.password) throw new BadRequestException('Confirm password and password do not match')

        const hash = await bcrypt.hash(changePasswordDto.password, this.saltRounds);

        const user = await this.prisma.user.findUnique({
            where: {
                id: token.user_id
            }
        });
        await this.prisma.user.update({
            where: {
                id: user.id
            },
            data: {
                password: hash
            }
        })


        await this.prisma.token.delete({
            where: {
                id: token.id
            }
        });
        return true
    }

    async verifyEmail(verifyEmailDto: VerifyEmailDto) {
        const RTokens = await this.prisma.token.findMany({
            where: {
                type: TOKEN_TYPE.confirm_token
            }
        })

        if (RTokens.length < 1) throw new NotFoundException('user not found')

        let tokenExists: boolean = false
        let user_Id: string

        for (const token of RTokens) {
            const isValid = await bcrypt.compare(verifyEmailDto.token, token.token)

            if (isValid) {
                tokenExists = true
                user_Id = token.user_id
                await this.prisma.token.delete({
                    where: {
                        id: token.id
                    }
                })

                break
            }
        }

        if (!tokenExists) throw new NotFoundException('user not found')

        await this.prisma.user.update({
            where: {
                id: user_Id
            },
            data: {
                emailConfirmed: true
            }
        })

        return `${process.env.CLIENT_URL}/login`

    }

    async logout(id: string): Promise<any> {
        const hashTokens = await this.prisma.token.findMany({
            where: {
                user_id: id,
                type: TOKEN_TYPE.refresh_token_hash
            }
        })

        if (hashTokens.length < 1) return { message: "loggedout" }

        await this.prisma.token.deleteMany({
            where: {
                user_id: id,
                type: TOKEN_TYPE.refresh_token_hash
            }
        })

        return { message: "loggedout" }
    }

    async logIn(loginDto: LoginDto): Promise<any> {
        const user = await this.prisma.user.findUnique({
            where: {
                email: loginDto.email
            }
        })

        if (!user) throw new BadRequestException('invalid credentials')

        const passwordMatch = await bcrypt.compare(
            loginDto.password,
            user.password,
        );

        if (!passwordMatch) throw new BadRequestException('invalid credentials')

        const tokens = await this.generateAuthTokens({ id: user.id })

        const userDetails = await this.userService.getUser({ id: user.id })

        return { tokens, user: userDetails }


    }

    async generateAuthTokens(generateAuthTokensDto: GenerateAuthTokensDto) {
        const expirationTime = new Date();
        expirationTime.setDate(expirationTime.getDate() + 3);

        const accessToken = jwt.sign(
            { id: generateAuthTokensDto.id },
            this.secretKey,
            { expiresIn: '15m' }
        )

        const refreshToken = await generateRandomAlphanumeric(53)
        const hash = await bcrypt.hash(refreshToken, this.saltRounds)

        const refreshTokenjsonwebtoken = jwt.sign(
            { id: generateAuthTokensDto.id, token: refreshToken },
            this.secretKey,
            { expiresIn: '3d' }
        )

        await this.prisma.token.create({
            data: {
                user_id: generateAuthTokensDto.id,
                type: TOKEN_TYPE.refresh_token_hash,
                token: hash,
                expire_at: expirationTime,

            },
        });

        return { accessToken, refreshToken: refreshTokenjsonwebtoken }
    }

    async refresh(refreshDto: RefreshDto) {
        const accessToken = jwt.sign(
            { id: refreshDto.id },
            this.secretKey,
            { expiresIn: '15m' }
        )

        return accessToken
    }
}
