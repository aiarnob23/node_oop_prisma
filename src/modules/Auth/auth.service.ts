import { BaseService } from "@/core/BaseService";
import { PrismaClient, User } from "@/generated/prisma";
import { RegisterInput } from "./auth.validation";


export class AuthService extends BaseService<User> {
    private readonly SALT_ROUNDS = 12;

    constructor(prisma: PrismaClient) {
        super(prisma, 'User', {
            enableAuditFields: true,
            enableSoftDelete: false,
        });
    }

    protected getModel() {
        return this.prisma.user;
    }

    /**
  * Register a new user
  */
 async register(
    data:RegisterInput
 ):Promise<{message:string; requiresVerification:boolean}>{

    return{
        message:'Registration successful. Please check your email for verification.',
        requiresVerification:true,
    }
 }


}