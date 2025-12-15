import { BaseModule } from "@/core/BaseModule";
import { TestService } from "./test.service";
import { TestController } from "./test.controller";
import { TestRoutes } from "./test.route";
import { AppLogger } from "@/core/ logging/logger";
import { prisma } from "@/core/prisma";

export class testModule extends BaseModule {
    public readonly name = "TestModule";
    public readonly version = "1.0.0";
    public readonly dependencies = [];

    private testService!: TestService;
    private testController!: TestController;
    private testRoutes!: TestRoutes;

    /**
   * Setup module services
   */
  protected async setupServices(): Promise<void> {
       // Initialize service
    this.testService = new TestService(prisma);
    AppLogger.info("EmployeeService initialized successfully");
  }

  protected async setupRoutes(): Promise<void> {
    this.testController = new TestController(this.testService);
    AppLogger.info("TestController initialized successfully");

    this.testRoutes = new TestRoutes(this.testController);
    AppLogger.info("TestRoutes initialized successfully");

    this.router.use("/api/test", this.testRoutes.getRouter());
  }

}