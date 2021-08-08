import { Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { ClientsModule, Transport } from '@nestjs/microservices';
import { AuthService } from './auth.service';
import { JwtStrategy } from './jwt.strategy';
import { LocalStrategy } from './local.strategy';
import { AuthController } from './auth.controller';

@Module({
  imports:[ClientsModule.register([{
    name: 'USER_CLIENT',
    transport: Transport.TCP,
    options:{
      host: 'localhost',
      port: 4010
    }
  }]),
  JwtModule.register({
    secret: 'yoursecret',
    signOptions: {expiresIn: '60s'}
  })
],
  providers: [AuthService, LocalStrategy, JwtStrategy],
  controllers: [AuthController]
})
export class AuthModule {}
