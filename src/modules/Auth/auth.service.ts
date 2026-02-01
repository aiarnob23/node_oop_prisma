import { BaseService } from "@/core/BaseService";
import { AccountStatus, PrismaClient, User, UserRole } from "@/generated/prisma";
import { ForgotPasswordInput, LoginInput, RegisterInput, ResendEmailVerificationInput, ResetPasswordInput, verifyEmailInput, VerifyResetPasswordOTPInput } from "./auth.validation";
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

export interface TokenInfo {
    userId: string;
    email: string;
    role: string;
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
   * Login user
   */
    async login(data: LoginInput): Promise<AuthResponse> {
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

    //password reset flow starts//
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
   * Verify reset password OTP
   */
    async verifyResetPasswordOTP(data: VerifyResetPasswordOTPInput): Promise<{ message: string }> {
        const { email, code } = data;

        try {
            // Find user
            const user = await this.findOne({ email });
            if (!user) {
                throw new NotFoundError('User not found');
            }

            // Verify OTP
            const otpResult = await this.otpService.verifyOTP({
                identifier: email,
                code,
                type: OTPType.password_reset,
            });

            if (!otpResult.success) {
                throw new BadRequestError('Invalid or expired reset code');
            }

            AppLogger.info('Password reset OTP verified successfully', {
                userId: user.id,
                email: user.email,
            });

            return {
                message:
                    'Password reset OTP verified successfully. You can now login with your new password.',
            };
        } catch (error) {
            AppLogger.error('Failed to verify reset password OTP', {
                email,
                error: error instanceof Error ? error.message : error,
            });

            // Rethrow so controller layer (Express, Nest, etc.) can format proper HTTP response
            throw error;
        }
    }

    /**
     * Reset password with OTP
     */
    async resetPassword(data: ResetPasswordInput): Promise<{ message: string }> {
        const { email, newPassword } = data;

        //check user exists
        const user = await this.findOne({ email });
        if (!user) {
            throw new NotFoundError('User not found');
        }

        // ✅ Ensure OTP was verified before allowing reset
        const hasVerifiedOTP = await this.hasVerifiedOTP(email, OTPType.password_reset);
        if (!hasVerifiedOTP) {
            throw new BadRequestError('Password reset OTP not verified');
        }

        // Hash and update password
        const hashedPassword = await this.hashPassword(newPassword);
        await this.updateById(user.id, { password: hashedPassword });

        this.otpService.cleanupUserOTPs(email);

        AppLogger.info('Password reset successfully', { userId: user.id, email: user.email });

        return {
            message: 'Password reset successfully. You can now log in with your new password.',
        };
    } //password reset flow ends//


    /**
     * Change user password (when logged in)
     */
    async changePassword(
        userId: string,
        currentPassword: string,
        newPassword: string
    ): Promise<{ message: string }> {
        // Find user using BaseService method
        const user = await this.findById(userId);
        if (!user) {
            throw new NotFoundError('User not found');
        }

        // Verify current password
        const isValidPassword = await this.verifyPassword(currentPassword, user.password);
        if (!isValidPassword) {
            throw new AuthenticationError('Current password is incorrect');
        }

        // Hash new password
        const hashedNewPassword = await this.hashPassword(newPassword);

        // Update password using BaseService method
        await this.updateById(userId, {
            password: hashedNewPassword,
        });

        AppLogger.info('Password changed successfully', { userId });

        return {
            message: 'Password changed successfully',
        };
    }

    /**
     * Get user profile by token
     */
    async getProfile(userId: string): Promise<Omit<User, 'password'>> {
        const user = await this.findById(userId);
        if (!user) {
            throw new NotFoundError('User');
        }

        const { password, ...userWithoutPassword } = user;

        return userWithoutPassword;
    }

    /**
     * Update user role (admin only)
     */
    async updateUserRole(userId: string, newRole: UserRole): Promise<Omit<User, 'password'>> {
        const user = await this.findById(userId);
        if (!user) {
            throw new NotFoundError('User');
        }

        const updatedUser = await this.updateById(userId, { role: newRole });

        AppLogger.info('User role updated', {
            userId,
            oldRole: user.role,
            newRole,
        });

        const { password, ...userWithoutPassword } = updatedUser;
        return userWithoutPassword;
    }

    /**
     * Get users with pagination (admin only)
     */
    async getUsers(pagination?: { page: number, limit: number }) {
        const users = await this.findMany(
            {},//no filters
            pagination,
            { createdAt: 'desc' },
            undefined,//no includes
        )

        return {
            ...users,
            data: users.data.map(({ password, ...rest }) => rest),
        };
    }

     /**
     * Verify JWT token and return user info
     */
    async verifyToken(token: string): Promise<TokenInfo> {
        try {
            if (!config.security.jwt.secret) {
                throw new AuthenticationError('JWT configuration missing');
            }

            const decoded = jwt.verify(token, config.security.jwt.secret) as JWTPayload;

            // Optionally verify user still exists and is active using BaseService method
            const user = await this.findById(decoded.id);
            if (!user) {
                throw new AuthenticationError('User not found');
            }

            if (user.status !== AccountStatus.active) {
                throw new AuthenticationError('Account is not active');
            }

            return {
                userId: decoded.id,
                email: decoded.email,
                role: decoded.role,
            };
        } catch (error) {
            if (error instanceof jwt.JsonWebTokenError) {
                throw new AuthenticationError('Invalid token');
            }
            if (error instanceof jwt.TokenExpiredError) {
                throw new AuthenticationError('Token expired');
            }
            throw error;
        }
    }

      /**
     * Refresh token
     */
    async refreshToken(currentToken: string): Promise<AuthResponse> {
        try {
            if (!config.security.jwt.secret) {
                throw new AuthenticationError('JWT configuration missing');
            }

            // Verify current token
            const decoded = jwt.verify(currentToken, config.security.jwt.secret) as JWTPayload;

            // Get fresh user data using BaseService method
            const user = await this.findById(decoded.id);
            if (!user) {
                throw new NotFoundError('User not found');
            }

            // Check if user is still active
            if (user.status !== AccountStatus.active) {
                throw new AuthenticationError('Account is not active');
            }

            AppLogger.info('Token refreshed successfully', {
                userId: user.id,
                email: user.email,
            });

            return this.generateAuthResponse(user);
        } catch (error) {
            if (error instanceof jwt.TokenExpiredError) {
                throw new AuthenticationError('Token expired');
            }
            if (error instanceof jwt.JsonWebTokenError) {
                throw new AuthenticationError('Invalid token');
            }
            throw error;
        }
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

    /**
    * Check if user has verified OTP for a specific type
    */
    private async hasVerifiedOTP(identifier: string, type: OTPType): Promise<boolean> {
        const otp = await this.prisma.oTP.findFirst({
            where: { identifier, type, verified: true },
            orderBy: { createdAt: 'desc' },
        });
        return !!otp;
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