import { Injectable, UnauthorizedException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import * as bcrypt from 'bcrypt';
import { JwtService } from '@nestjs/jwt';
import { User } from './user.entity';
import { LoginDto } from './login.dto';

@Injectable()
export class AuthService {
  constructor(
    @InjectRepository(User) private usersRepo: Repository<User>,
    private jwtService: JwtService,
  ) {}

  private sanitize(user: User) {
    const { password, ...safe } = user as any;
    return safe;
  }

  async validateUser(email: string, plainPassword: string) {
    const user = await this.usersRepo.findOne({ where: { email } });
    if (!user) return null;

    const match = await bcrypt.compare(plainPassword, user.password);
    if (!match) return null;

    return this.sanitize(user);
  }

  async login(dto: LoginDto) {
    const user = await this.usersRepo.findOne({ where: { email: dto.email } });
    if (!user) throw new UnauthorizedException('Credenciales inválidas');

    const passwordMatches = await bcrypt.compare(dto.password, user.password);
    if (!passwordMatches)
      throw new UnauthorizedException('Credenciales inválidas');

    const payload = { sub: user.id, email: user.email };
    const token = this.jwtService.sign(payload);

    return {
      access_token: token,
      user: this.sanitize(user),
    };
  }
}
