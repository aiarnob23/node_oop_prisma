import { BaseModule } from "@/core/BaseModule";
import { AuthService } from "./auth.service";
import { AuthController } from "./auth.controller";
import { AuthRoutes } from "./auth.route";
import { config } from "@/core/config";
import { AppLogger } from "@/core/ logging/logger";



export class AuthModule extends BaseModule {

    public readonly name = 'AuthModule';
    public readonly version = '1.0.0';
    public readonly dependencies = [];

    private authService!: AuthService;
    private authController!: AuthController;
    private authRoutes!: AuthRoutes;

    /**
     * Setup module services
     */
    protected async setupServices(): Promise<void> {
        if (!config.security.jwt.secret) {
            throw new Error('JWT_SECRET is required in environment variables');
        }

        //Initialize service
        this.authService = new AuthService(this.context.prisma);
        AppLogger.info('AuthService initialized successfully');
    }

    /** 
     * Setup module routes
     */
    protected async setupRoutes(): Promise<void> {
        // Initialize controller
        this.authController = new AuthController(this.authService);
        AppLogger.info('AuthController initialized successfully');

        // Initialize routes
        this.authRoutes = new AuthRoutes(this.authController);
        AppLogger.info('AuthRoutes initialized successfully');

        // Mount routes under /api/auth
        this.router.use('/api/auth', this.authRoutes.getRouter());
    }


}