import { Request, Response, Router } from "express";
import { TestController } from "./test.controller";
import { asyncHandler } from "@/middleware/asyncHandler";
import { validateRequest } from "@/middleware/validation";
import { TestValidation } from "./test.validation";


export class TestRoutes {
    private router: Router;
    private testController: TestController;

    constructor(testController: TestController) {
        this.router = Router();
        this.testController = testController;
        this.initializeRoutes();
    }

    // initialize router\s
    private initializeRoutes(): void {

        //create new test
        this.router.post(
            "/",
            validateRequest({
                body:TestValidation.body.create,
            }),
            asyncHandler((req: Request, res: Response) =>
                this.testController.createTest(req, res))
        )
    }

    //get router
    public getRouter(): Router {
        return this.router;
    }
}