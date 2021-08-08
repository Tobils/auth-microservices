import { Inject, Injectable, Logger, RequestTimeoutException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { ClientProxy } from '@nestjs/microservices';
import { compareSync } from 'bcrypt';
import { catchError, throwError, timeout, TimeoutError } from 'rxjs';
import { CreateUserDto } from './dto/create-user.dto';
import * as bcrypt from 'bcrypt';

@Injectable()
export class AuthService {
    constructor(
        @Inject('USER_CLIENT')
        private readonly client: ClientProxy,
        private readonly jwtService: JwtService
    ){}
    private logger: Logger = new Logger(AuthService.name)

    async validateUser(
        username:string,
        password: string
    ): Promise<any>
    {
        try {
            const user = await this.client.send({role: 'user', cmd: 'get'}, {username})
                .pipe(
                    timeout(5000),
                    catchError(err => {
                        if(err instanceof TimeoutError){
                            return throwError(new RequestTimeoutException())
                        }
                        return throwError(err)
                    })
                )
                .toPromise();
            if(typeof user === 'undefined'){
                return null
            }

            const __is_match = await this.validatePassword(password, user?.password)
            if(__is_match){
                return user
            } else{
                return null
            }
        } catch (error) {
            this.logger.error(error)
            throw error;
        }
    }

    async signin(user){
        const payload = {user, sub: user.id};

        return {
            userId: user.id,
            accessToken: this.jwtService.sign(payload)
        }
    }

    async signup(createUserDto: CreateUserDto){
        try {
            return await this.client.send({role: 'user', cmd: 'create'}, {...createUserDto})
                
        } catch (error) {
            this.logger.error(error)
            throw error;
        }
    }

    async validatePassword(password: string, hashPassword: string): Promise<boolean> {
        const isMatch = await bcrypt.compare(password, hashPassword)
        return isMatch;
    }

    async validateToken(jwt: string){
        return this.jwtService.verify(jwt)
    }


}
