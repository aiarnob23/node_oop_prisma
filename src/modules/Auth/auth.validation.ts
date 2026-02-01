
import { password } from 'bun';
import { z } from 'zod';

// --------------------
// ENUM SCHEMAS 
// --------------------

const roleSchema = z.enum(['user', 'admin']);

const accountStatusSchema = z.enum([
    'active',
    'inactive',
    'suspended',
    'pending_verification',
])

const otpTypeSchema = z.enum([
    'email_verification',
    'login_verification',
    'password_reset',
    'two_factor',
]);

// Email 
const emailSchema = z
    .string()
    .email('Invalid email address')
    .min(5)
    .max(255)
    .transform(v => v.toLowerCase().trim());

// Password 
const passwordSchema = z
    .string()
    .min(8, 'Password must be at least 8 characters')
    .max(128, 'Password must not exceed 128 characters')
    .regex(/^(?=.*[a-z])/, 'Must contain one lowercase letter')
    .regex(/^(?=.*[A-Z])/, 'Must contain one uppercase letter')
    .regex(/^(?=.*\d)/, 'Must contain one number');

// Otp
const otpCodeSchema = z
    .string()
    .regex(/^\d{6}$/, 'OTP must be exactly 6 digits')
    .transform(v => Number(v));


// Username
const usernameSchema = z
    .string()
    .min(3, 'Username must be at least 3 characters')
    .max(50)
    .regex(/^[a-zA-Z0-9_]+$/, 'Username can only contain letters, numbers and _')
    .trim();



// --------------------
// AUTH VALIDATIONS
// --------------------

export const AuthValidation = {
    // --------------------
    // REGISTER
    // --------------------
    register: z
        .object({
            email: emailSchema,
            password: passwordSchema,
            confirmPassword: passwordSchema,
            firstName: z
                .string()
                .min(2, 'First name must be at least 2 characters')
                .max(100, 'First name must not exceed 100 characters')
                .trim()
                .optional(),
            lastName: z
                .string()
                .min(2, 'Last name must be at least 2 characters')
                .max(100, 'Last name must not exceed 100 characters')
                .trim()
                .optional(),
            role: roleSchema.optional(),
        })
        .strict()
        .refine(data => data.password === data.confirmPassword, {
            message: 'Passwords do not match',
            path: ['confirmPassword'],
        })
        .transform(data => {
            const { confirmPassword, ...rest } = data;
            return rest;
        }),

    // --------------------
    // Login Validation
    // --------------------
    login: z
        .object({
            email: emailSchema,
            password: z.string().min(1, 'Password is required'),
        })
        .strict(),

    // --------------------
    // Email Verification Validation
    // --------------------
    verifyEmail: z
        .object({
            email: emailSchema,
            code: otpCodeSchema,
        })
        .strict(),
    // Resend email verification validation
    resendEmailVerification: z
        .object({
            email: emailSchema,
        })
        .strict(),
    // Forgot password validation
    forgotPassword: z
        .object({
            email: emailSchema,
        })
        .strict(),

    // Password reset OTP validation
    verifyResetPasswordOTPInput: z
        .object({
            email: emailSchema,
            code: otpCodeSchema,
        })
        .strict(),
    //reset password validation
    resetPassword: z
        .object({
            email: emailSchema,
            newPassword: passwordSchema,
        })
        .strict(),
    // Change password validation
    changePassword: z
        .object({
            currentPassword: z.string().min(1, 'Current password is required'),
            newPassword: passwordSchema,
            confirmNewPassword: z.string(),
        })
        .strict()
        .refine(data => data.newPassword === data.confirmNewPassword, {
            message: 'New passwords do not match',
            path: ['confirmNewPassword'],
        })
        .refine(data => data.currentPassword !== data.newPassword, {
            message: 'New password must be different from current password',
            path: ['newPassword'],
        })
        .transform(data => {
            // Remove confirmNewPassword from the final object
            const { confirmNewPassword, ...rest } = data;
            return rest;
        }),  
    // Update role validation (admin only)
    updateRole: z
        .object({
            role: roleSchema,
        })
        .strict(),
        // Refresh token validation
    refreshToken: z
        .object({
            token: z.string().min(1, 'Token is required').optional(), 
        })
        .strict(),
    // Parameter validation
    params: {
        userId: z.object({
            userId: z.string().min(1, 'User ID is required').uuid('User ID must be a valid UUID'),
        }),
    },
}

//Type exports
export type RegisterInput = z.infer<typeof AuthValidation.register>;
export type LoginInput = z.infer<typeof AuthValidation.login>;
export type verifyEmailInput = z.infer<typeof AuthValidation.verifyEmail>;
export type ResendEmailVerificationInput = z.infer<typeof AuthValidation.resendEmailVerification>;
export type ForgotPasswordInput = z.infer<typeof AuthValidation.forgotPassword>;
export type UpdateRoleInput = z.infer<typeof AuthValidation.updateRole>;
export type VerifyResetPasswordOTPInput = z.infer<
    typeof AuthValidation.verifyResetPasswordOTPInput
>;
export type ResetPasswordInput = z.infer<typeof AuthValidation.resetPassword>;