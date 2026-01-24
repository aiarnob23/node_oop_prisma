import { BaseService } from "@/core/BaseService";
import { AccountStatus, PrismaClient, User, UserRole } from "@/generated/prisma";
import { ForgotPasswordInput, LoginInput, RegisterInput, ResendEmailVerificationInput, verifyEmailInput } from "./auth.validation";
import jwt from 'jsonwebtoken';
import { OTPService, OTPType } from "@/services/otp.service";
import SESEmailService from "@/services/SESEmailService";
import bcrypt from 'bcrypt';
import { AppError, AuthenticationError, BadRequestError, ConflictError, NotFoundError } from "@/core/errors/AppError";
import { AppLogger } from "@/core/ logging/logger";
import { config } from "@/core/config";
import { JWTPayload } from "@/middleware/auth";
import { HTTPStatusCode } from "@/types/HTTPStatusCode";

export interface AuthResponse {
    user: Omit<User, 'password'>;
    token: string;
    expiresIn: string;
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
     * Login user
     */
    async Login(data: LoginInput): Promise<AuthResponse> {
        const { email, password } = data;

        //Find user by email
        const user = await this.findOne({ email });
        if (!user) {
            throw new AuthenticationError('Invalid email or password');
        }

        //check if user is verified
        if (user.status === AccountStatus.pending_verification) {
            throw new AuthenticationError('Please verify your email first', {
                requiresVerification: true,

            });
        }

        //check if user is active
        if (user.status !== AccountStatus.active) {
            throw new AuthenticationError('Account is not active');
        }

        //verify password
        const isValidPassword = await this.verifyPassword(password, user.password);

        if (!isValidPassword) {
            AppLogger.warn('Failed login attempt', { email, userId: user.id });
            throw new AuthenticationError('Invalid email or password');
        }

        AppLogger.info('User logged in successfully', {
            userId: user.id,
            email: user.email,
            role: user.role,
        });


        return this.generateAuthResponse(user);
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
    * Resend email verification OTP
    */
    async resendEmailVerification(
        data: ResendEmailVerificationInput
    ): Promise<{ message: string }> {
        const { email } = data;

        // Find user using BaseService method
        const user = await this.findOne({ email: email });
        if (!user) {
            throw new NotFoundError('User not found');
        }

        if (user.status === AccountStatus.active) {
            throw new BadRequestError('Email already verified');
        }

        await this.otpService.sendOTP({
            identifier: email,
            type: OTPType.email_verification,
            userId: user.id,
        });

        AppLogger.info('Email verification OTP resent', {
            userId: user.id,
            email: user.email,
        });

        return {
            message: 'Verification code sent to your email',
        };
    }

    /**
     * Forgot Password - send reset code
     */
    async forgotPassword(data: ForgotPasswordInput): Promise<{ message: string }> {
        const { email } = data;

        //find user
        const user = await this.findOne({ email });
        if (!user) {
            // Don't reveal if email exists or not for security
            return {
                message:
                    'If an account with this email exists, you will receive a password reset code.',
            };
        }

        if (user.status !== AccountStatus.active) {
            return {
                message:
                    'If an account with this email exists, you will receive a password reset code.',
            };
        }

        try {
            await this.otpService.sendOTP({
                identifier: email,
                type: OTPType.password_reset,
                userId: user.id,
            });

            AppLogger.info('Password reset OTP sent', {
                userId: user.id,
                email: user.email,
            });
        } catch (error) {
            AppLogger.error('Failed to send password reset OTP', {
                userId: user.id,
                email: user.email,
                error: error instanceof Error ? error.message : 'Unknown error',
            });
            throw new AppError(
                HTTPStatusCode.BAD_REQUEST,
                error instanceof Error ? error.message : 'Unknown error',
                'Failed to send password reset OTP'
            );
        }

        return {
            message:
                'If an account with this email exists, you will receive a password reset code.',
        };
    }


    /**
    * Hash password using bcrypt
    */
    private async hashPassword(password: string): Promise<string> {
        return bcrypt.hash(password, this.SALT_ROUNDS);
    }

    /**
     * Verify password using bcrypt
     */
    private async verifyPassword(plainPassword: string, hashedPassword: string): Promise<boolean> {
        return bcrypt.compare(plainPassword, hashedPassword);
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