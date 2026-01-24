import { Request, Response, Router } from "express";
import { AuthController } from "./auth.controller";
import { validateRequest } from "@/middleware/validation";
import { AuthValidation } from "./auth.validation";
import { asyncHandler } from "@/middleware/asyncHandler";

export class AuthRoutes {
    private router: Router;
    private authController: AuthController;

    constructor(authController: AuthController) {
        this.router = Router();
        this.authController = authController;
        this.initialized();
    }

    private initialized(): void {
        // Public routes (no authentication required)

        // Register new user
        this.router.post(
            '/register',
            validateRequest({
                body: AuthValidation.register,
            }),
            asyncHandler((req: Request, res: Response) => this.authController.register(req, res))
        );

        // Login user
        this.router.post(
            '/login',
            validateRequest({
                body: AuthValidation.login,
            }),
            asyncHandler((req: Request, res: Response) => this.authController.login(req, res))
        );

        //verify email
        this.router.post(
            '/verify-email',
            validateRequest({
                body: AuthValidation.verifyEmail,
            }),
            asyncHandler((req: Request, res: Response) => this.authController.verifyEmail(req, res))
        )

        // Resend email verification
        this.router.post(
            '/resend-email-verification',
            validateRequest({
                body: AuthValidation.resendEmailVerification,
            }),
            asyncHandler((req: Request, res: Response) =>
                this.authController.resendEmailVerification(req, res)
            )
        );

        // Forgot password - send reset code
        this.router.post(
            '/forgot-password',
            validateRequest({
                body: AuthValidation.forgotPassword,
            }),
            asyncHandler((req: Request, res: Response) =>
                this.authController.forgotPassword(req, res)
            )
        );

    }

    public getRouter(): Router {
        return this.router;
    }
}