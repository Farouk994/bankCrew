import { Injectable } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { jwtConstants } from '../constants';

@Injectable()
export class RefreshTokenStrategy extends PassportStrategy(
  Strategy,
  'jwt-refresh',
) {
  constructor() {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      secretOrKey: jwtConstants.secret,
      passReqToCallback: true,
    });
  }

  validate(req: Request, payload: any) {
    // const refreshToken = req.headers['authorization'].replace('Bearer','').trim();
    const refreshToken = req.headers['Authorization'] || req.headers['authorization'];

    return { ...payload, refreshToken}
  }
}
