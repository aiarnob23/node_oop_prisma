import { BaseController } from "@/core/BaseController";
import { AuthService } from "./auth.service";
import { Request, Response } from "express";
import { HTTPStatusCode } from "@/types/HTTPStatusCode";

export class AuthController extends BaseController {
    constructor(private authService: AuthService) {
        super()
    }

    /**
     * Register a new user
     * POST /api/auth/register
     */
    public register = async (req: Request, res: Response) => {
        const body = req.validatedBody || req.body;
        this.logAction('register', req, { email: body.email, role: body.role });

        const result = await this.authService.register(body);

        return this.sendCreatedResponse(res, result, 'User registered successfully');
    }

    /**
     * Login user
     * POST /api/auth/login
     */
    public login = async (req: Request, res: Response) => {
        const body = req.validatedBody || req.body;
        this.logAction('login', req, { email: body.email });

        const result = await this.authService.Login(body);

        this.setAuthCookie(res, result.token);

        return this.sendResponse(res, 'Login successful', HTTPStatusCode.OK, result);
    }

    /**
  * Verify email
  * POST /api/auth/verify-email
  */
    public verifyEmail = async (req: Request, res: Response) => {
        const body = req.validatedBody || req.body;
        this.logAction('verifyEmail', req, { email: body.email });

        const result = await this.authService.verifyEmail(body);

        this.setAuthCookie(res, result.token);

        return this.sendResponse(res, 'Login Successful', HTTPStatusCode.OK, result);
    }

    /**
     * Resend verification email
     * POST /api/auth/resend-verification-email
     */
    public resendEmailVerification = async (req: Request, res: Response) => {
        const body = req.validatedBody || req.body;
        this.logAction('resendEmailVerification', req, { email: body.email });

        const result = await this.authService.resendEmailVerification(body);

        return this.sendResponse(
            res,
            'Verification email sent successfully',
            HTTPStatusCode.OK,
            result
        );
    };

    /**
     * Forgot password - send reset code
     * POST /api/auth/forgot-password
     */
    public forgotPassword = async (req: Request, res: Response) => {
        const body = req.validatedBody || req.body;
        this.logAction('forgotPassword', req, { email: body.email });

        const result = await this.authService.forgotPassword(body);

        return this.sendResponse(
            res,
            'Password reset instructions sent',
            HTTPStatusCode.OK,
            result
        );
    };
}