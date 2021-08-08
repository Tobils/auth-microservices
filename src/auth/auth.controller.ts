import { Controller, Post, UseGuards, Request, Body, Logger } from '@nestjs/common';
import { MessagePattern } from '@nestjs/microservices';
import { AuthService } from './auth.service';
import { CreateUserDto } from './dto/create-user.dto';
import { LocalAuthGuard } from './local-auth-guard';


@Controller('auth')
export class AuthController {
    constructor(
        private readonly authSevice: AuthService
    ){}

    @UseGuards(LocalAuthGuard)
    @Post('/signin')
    async signin(
        @Request() req
    ){
        return this.authSevice.signin(req.user)
    }

    @Post('/signup')
    async signup(
        @Body() createUserDto: CreateUserDto
    ){
        return this.authSevice.signup(createUserDto)
    }

    @MessagePattern({ role: 'auth', cmd: 'check'})
    async loggedIn(data){
        try {
            return this.authSevice.validateToken(data.jwt)
        } catch (error) {
            Logger.error(error)
            return false
        }
    }
}
