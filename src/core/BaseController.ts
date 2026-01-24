import { Request, Response } from "express";
import { HTTPStatusCode } from "../types/HTTPStatusCode";
import { ApiResponse } from "../types/types";
import { AppLogger } from "./ logging/logger";
import { config } from "./config";

export abstract class BaseController {

    // send a successful response
    protected sendResponse<T>(
        res: Response,
        message?: string,
        statusCode: HTTPStatusCode = HTTPStatusCode.OK,
        data?: T
    ): Response<ApiResponse<T>> {

        const response: ApiResponse<T> = {
            success: true,
            message,
            meta: {
                requestId: (res.req as any).id,
                timestamp: new Date().toISOString(),
            },
            data,
        }

        return res.status(statusCode).json(response);
    }

    //send a created response
    protected sendCreatedResponse<T>(
        res: Response,
        data: T,
        message: string = 'Resource created successfully'
    ): Response<ApiResponse<T>> {
        return this.sendResponse(res, message, HTTPStatusCode.CREATED, data);
    }

    /**
    * Set secure HTTP-only cookie for authentication token
    */
    protected setAuthCookie(res: Response, token: string): void {
        const cookieName = 'auth_token';
        const maxAge = 24 * 60 * 60 * 1000 //24h

        // Check if we are in a production environment (HTTPS)
        const isProduction = config.server.isProduction;

        // In Production, 'None' allows cross-site POST (needed for payment redirects).
        res.cookie(cookieName, token, {
            httpOnly: true,
            secure: true,
            sameSite: 'none',
            maxAge,
            path: '/',
        })

        // Debug logging in non-production
        if (!isProduction) {
            console.log('🍪 Auth Cookie Set:', {
                name: cookieName,
                secure: isProduction,
                sameSite: isProduction ? 'none' : 'lax',
                env: config.server.env,
            });
        }
    }

    /**
   * Set secure HTTP-only cookie for various purposes
   */
    protected setCookie(res: Response, name: string, value: string, maxAge: number): void {
        res.cookie(name, value, {
            httpOnly: true,
            secure: true,
            sameSite: 'none',
            maxAge,
            path: '/',
        });
    }


    /**
     * Log controller action
     */
    protected logAction(action: string, req: Request, metaData?: any): void {
        AppLogger.info(`Controller action : ${action}`, {
            requestId: (req as any).id,
            userId: (req as any).userId,
            method: req.method,
            path: req.path,
            ...metaData
        })
    }

    /**
      * Extract user ID from request (assuming it's set by auth middleware)
      */
    protected getUserId(req: Request): string | undefined {
        return (req as any).userId;
    }

}