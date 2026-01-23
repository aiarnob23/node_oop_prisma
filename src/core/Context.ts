import { PrismaClient } from "@/generated/prisma";
import { AppLogger } from "./ logging/logger";
import { config } from "./config";
import { prisma } from "./prisma";

export class Context {
    public config: typeof config;
    public prisma : PrismaClient;

    constructor() {
        this.config = config;
        this.prisma = prisma;
    }

    //DB initialization
    public async initialize(): Promise<void> {
        try {
            await prisma.$connect();
            AppLogger.info('🗄️ Database connected successfully');

        }
        catch (error) {
            AppLogger.error('❌ Database connection failed', error);
            throw error;
        }
    }

    //DB shutdown
    public async shutdown(): Promise<void> {
        try {
            await prisma.$disconnect();
            AppLogger.info('🗄️ Database disconnected successfully');
        } catch (error) {
            AppLogger.error('❌ Database disconnection failed', error);
            throw error;
        }
    }
}