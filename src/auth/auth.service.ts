import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { LoginUserDto, RegisterUserDto } from './dto';
import { PrismaClient } from '@prisma/client';

import * as bcrypt from 'bcrypt';

import { RpcException } from '@nestjs/microservices';
import { JwtService } from '@nestjs/jwt';
import { JWTPayload } from './interfaces/jwt-payload.interfaces';
import { envs } from 'src/config/envs';

@Injectable()
export class AuthService extends PrismaClient implements OnModuleInit {

    private readonly logger = new Logger('Auth Services MS')

    constructor(private jwtService: JwtService) {
        super();
    }

    onModuleInit() {
        this.$connect()
        this.logger.log('Mongo db connected')
    }

    async signJWT(payload: JWTPayload) {
        return this.jwtService.sign(payload)
    }

    async registerUser(registerUserDto: RegisterUserDto) {
        try {
            const { name, email, password } = registerUserDto
            const user = await this.user.findUnique({
                where: {
                    email: email
                }
            })
            if (user) {
                throw new RpcException({
                    status: 400,
                    message: 'User already exist'
                })
            }

            const newUser = await this.user.create({ data: { email, password: bcrypt.hashSync(password, 10), name } })
            const { password: pw, ...resUser } = newUser
            return {
                user: resUser,
                token: await this.signJWT(resUser)
            }
        } catch (error) {
            throw new RpcException({
                status: 400,
                message: error.message
            })
        }
    }

    async loginUser(loginUsetDto: LoginUserDto) {

        try {
            const { email, password } = loginUsetDto
            const user = await this.user.findUnique({
                where: {
                    email
                }
            })
            if (!user) {
                throw new RpcException({
                    status: 400,
                    message: 'User/Password invalidate credentials'
                })
            }

            const isPasswordValid = await bcrypt.compare(password, user.password);

            if (!isPasswordValid) {
                throw new RpcException({
                    status: 400,
                    message: 'Password not valid'
                })
            }

            const { password: _, ...rest } = user
            return {
                user: rest,
                token: await this.signJWT(rest)
            };
        } catch (error) {
            throw new RpcException({
                status: 400,
                message: error.message
            })
        }

    }

    async verifyToken(token: string) {

        try {
            const { sub, iat, exp, ...user } = this.jwtService.verify(token, {
                secret: envs.jwtSecret
            })

            return {
                user,
                token: await this.signJWT(user)
            }


        } catch (error) {
            throw new RpcException({
                status: 401,
                message: 'Invalid token'
            })
        }
    }
}
