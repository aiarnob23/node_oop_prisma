
import { Response } from "express";
import { HTTPStatusCode } from "../types/HTTPStatusCode";
import { ApiResponse } from "../types/types";


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
        res:Response,
        data:T,
        message:string = 'Resource created successfully'
    ):Response<ApiResponse<T>>{
       return this.sendResponse(res,message,HTTPStatusCode.CREATED,data);
    }
}