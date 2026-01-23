import { PrismaClient } from "@/generated/prisma";
import { AppLogger } from "./ logging/logger";
import { DatabaseError, NotFoundError } from "./errors/AppError";

export interface BaseServiceOptions {
    enableSoftDelete?: boolean;
    enableAuditFields?: boolean;
    defaultPageSize?: number;
    maxPageSize?: number;
}

export abstract class BaseService<TModel = any, TCreateInput = any, TUpdateInput = any> {

    protected prisma: PrismaClient;
    protected modelName: string;
    protected options: BaseServiceOptions;

    constructor(prisma: PrismaClient, modelName: string, options: BaseServiceOptions = {}) {
        this.prisma = prisma;
        this.modelName = modelName;
        this.options = {
            enableSoftDelete: false,
            enableAuditFields: false,
            defaultPageSize: 10,
            maxPageSize: 1000,
            ...options,
        };
    }

    protected abstract getModel(): any;

    //find one
    protected async findOne(filters: any, include?: any): Promise<TModel | null> {
        try {
            return this.getModel().findFirst({ where: filters, include });
        }
        catch (error) {
            return this.handleDatabaseError(error, 'findOne');
        }
    }

    //create
    protected async create(data: TCreateInput, include?: any): Promise<TModel> {
        try {
            const createData = this.options.enableAuditFields
                ? { ...data, createdAt: new Date(), updatedAt: new Date() }
                : data

            return await this.getModel().create({ data: createData, include });
        } catch (error) {
            return this.handleDatabaseError(error, 'create');
        }
    }


     //handle database
    private handleDatabaseError(error: any, operation: string): never {
        AppLogger.error(`Database error in ${this.modelName}.${operation}`, { error });
        if (error.code === 'P2025') throw new NotFoundError(`${this.modelName} not found`);
        throw new DatabaseError(`Database operation failed: ${this.modelName}.${operation}`, { originalError: error.message, code: error.code });
    }
}