import { 
    ForbiddenException,
    Injectable 
} from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import { JwtService } from "@nestjs/jwt";
import { PrismaClientKnownRequestError } from "@prisma/client/runtime/library";
import * as argon from "argon2";
import { PrismaService } from "../prisma/prisma.service";
import { AuthDto } from "./dto";

@Injectable()
export class AuthService {
    constructor(
        private prisma: PrismaService,
        private jwt: JwtService,
        private config: ConfigService
    ) {}
    
    async signup(dto: AuthDto) {
        try {
            const 
                { email, password } = dto,
                passHash = await argon.hash(password),
                newUser = await this.prisma.user.create({ data: { email, passHash } });
    
            return this.signToken( newUser.id, newUser.email );
        } catch (error) {
            if (error instanceof PrismaClientKnownRequestError && error.code === "P2002") {
                throw new ForbiddenException("Email already exists");
            }

            throw error;
        }
    }

    async login(dto: AuthDto) {
        const 
            { email, password } = dto,
            user = await this.prisma.user.findUnique( { where: { email } } ),
            passValid = user && await argon.verify( user.passHash, password );

        if ( !user ?? !passValid ) throw new ForbiddenException( "Bad credentials" );

        return this.signToken( user.id, user.email );
    }

    async signToken( id: number, email: string ): Promise<{ token: String }> {
        const 
            expiresIn = "1d",
            secret = this.config.get( "JWT_SECRET" ),
            payload = { id, email },
            token = await this.jwt.signAsync( payload, { expiresIn, secret } );

        return { token };
    }
}