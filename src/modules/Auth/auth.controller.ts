import { BaseController } from "@/core/BaseController";
import { AuthService } from "./auth.service";
import { Request, Response } from "express";

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
}