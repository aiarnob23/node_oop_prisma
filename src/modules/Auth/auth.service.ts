import { BaseService } from "@/core/BaseService";
import { AccountStatus, PrismaClient, User, UserRole } from "@/generated/prisma";
import { RegisterInput, verifyEmailInput } from "./auth.validation";
import jwt from 'jsonwebtoken';
import { OTPService, OTPType } from "@/services/otp.service";
import SESEmailService from "@/services/SESEmailService";
import bcrypt from 'bcrypt';
import { AuthenticationError, BadRequestError, ConflictError, NotFoundError } from "@/core/errors/AppError";
import { AppLogger } from "@/core/ logging/logger";
import { config } from "@/core/config";
import { JWTPayload } from "@/middleware/auth";

export interface AuthResponse{
    user:Omit<User,'password'>;
    token:string;
    expiresIn:string;
}


export class AuthService extends BaseService<User> {
    private readonly SALT_ROUNDS = 12;
    private otpService: OTPService;

    constructor(prisma: PrismaClient) {
        super(prisma, 'User', {
            enableAuditFields: true,
            enableSoftDelete: false,
        });

        //Initialize OTP service
        this.otpService = new OTPService(this.prisma, new SESEmailService());
    }

    protected getModel() {
        return this.prisma.user;
    }

    /**
      * Register a new user
      */
    async register(
        data: RegisterInput
    ): Promise<{ message: string; requiresVerification: boolean }> {

        const { email, password, firstName, lastName, role = UserRole.user } = data;

        //check if user already exists
        const existingUser = await this.findOne({ email });
        if (existingUser) {
            throw new ConflictError('User with this email already exists');
        }

        //Hash password
        const hashedPassword = await this.hashPassword(password);

        //Create user with pending verification status
        const user = await this.create({
            email,
            password: hashedPassword,
            firstName: firstName,
            lastName: lastName,
            role,
            status: AccountStatus.pending_verification,
        })

        //Send OTP for email verification
        try {
            await this.otpService.sendOTP({
                identifier: email,
                type: OTPType.email_verification,
                userId: user.id,
            });

            AppLogger.info('User registered successfully, email verification sent', {
                userId: user.id,
                email: user.email,
                role: user.role,
            });

            return {
                message: 'Registration successful. Please check your email for verification.',
                requiresVerification: true,
            }
        } catch (error) {
            // If OTP sending fails, still allow registration but log the error
            AppLogger.error('Failed to send verification email after registration', {
                userId: user.id,
                email: user.email,
                error: error instanceof Error ? error.message : 'Unknown error',
            });

            return {
                message:
                    'Registration successful, but verification email failed to send. Please try to verify later.',
                requiresVerification: true,
            };
        }

    }

    /**
     * Verify email with OTP
     */
    async verifyEmail(data: verifyEmailInput): Promise<AuthResponse> {
        const { email, code } = data;

        // Find user using BaseService method
        const user = await this.findOne({ email });
        if (!user) {
            throw new NotFoundError('User not found');
        }

        // Check if already verified
        if (user.status === AccountStatus.active) {
            throw new BadRequestError('Email Already Verified');
        }

        // Verify OTP
        const otpResult = await this.otpService.verifyOTP({
            identifier: email,
            code,
            type: OTPType.email_verification,
        })

        if (!otpResult.success) {
            throw new BadRequestError('Invalid or Expired verification code');
        }

        // Update user status to active using BaseService method
        const updateUser = await this.updateById(user.id, {
            status: AccountStatus.active,
            emailVerifiedAt: new Date(),
        });


        AppLogger.info('Email verified successfully', {
            userId: user.id,
            email: user.email,
        });

        return this.generateAuthResponse(updateUser);
    }



    /**
    * Hash password using bcrypt
    */
    private async hashPassword(password: string): Promise<string> {
        return bcrypt.hash(password, this.SALT_ROUNDS);
    }

    //Generate Auth Response 
     private generateAuthResponse(user: User): AuthResponse {
        if (!config.security.jwt.secret) {
            throw new AuthenticationError('JWT configuration missing');
        }

        const payload: JWTPayload = {
            id: user.id,
            email: user.email,
            role: user.role,
        };

        const token = jwt.sign(payload, config.security.jwt.secret, {
            expiresIn: '1d',
        });

        const { password, ...userWithoutPassword } = user;

           return {
            user: userWithoutPassword,
            token,
            expiresIn: config.security.jwt.expiresIn || '1d',
        };
    }


}