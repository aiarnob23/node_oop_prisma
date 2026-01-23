import { BaseService } from "@/core/BaseService";
import { AccountStatus, PrismaClient, User, UserRole } from "@/generated/prisma";
import { RegisterInput, verifyEmailInput } from "./auth.validation";
import { OTPService, OTPType } from "@/services/otp.service";
import SESEmailService from "@/services/SESEmailService";
import bcrypt from 'bcrypt';
import { ConflictError } from "@/core/errors/AppError";
import { AppLogger } from "@/core/ logging/logger";


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
    // async verifyEmail(data:verifyEmailInput):Promise



    /**
    * Hash password using bcrypt
    */
    private async hashPassword(password: string): Promise<string> {
        return bcrypt.hash(password, this.SALT_ROUNDS);
    }


}