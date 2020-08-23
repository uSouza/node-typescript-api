import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import config from 'config';

export class AuthService {
  public static hashPassword(password: string, salt = 10): Promise<string> {
    return bcrypt.hash(password, salt);
  }

  public static comparePasswords(
    password: string,
    hashedPassword: string
  ): Promise<boolean> {
    return bcrypt.compare(password, hashedPassword);
  }

  // eslint-disable-next-line @typescript-eslint/ban-types
  public static generateToken(payload: object): string {
    return jwt.sign(payload, config.get('App.auth.key'), {
      expiresIn: config.get('App.auth.tokenExpiresIn'),
    });
  }
}
