import { AppLogger } from "@/core/ logging/logger";
import { BaseService } from "@/core/BaseService";
import { PrismaClient, Test } from "@/generated/prisma";
import { ConflictError } from "@/core/errors/AppError";
import { CreateTestInput } from "./test.validation";

export class TestService extends BaseService<Test> {

  constructor(prisma: PrismaClient) {
    super(prisma, "Test");
  }

  protected getModel() {
    return this.prisma.test;
  }

  /**
   * Create a new Test
   */
  async createTest(data: CreateTestInput) : Promise<Test> {
    const {email} = data;
    const existingTest = await this.findOne({email});

    if (existingTest) {
     AppLogger.warn(`Employee with email ${email} already exists.`);
      throw new ConflictError("Employee with this email already exists");
    }

     AppLogger.info(`Creating new Test: ${email}`);

    const newTest = await this.create({
      email
    });

    AppLogger.info(`New Test created: ${newTest.email} (ID: ${ newTest.id})`);

    return newTest;
  }




  //--------------------------------------------------//
  // static create(email: string) {
  //   return prisma.test.create({
  //     data: { email },
  //   });
  // }

  // static findAll() {
  //   return prisma.test.findMany();
  // }

  // static findById(id: string) {
  //   return prisma.test.findUnique({
  //     where: { id },
  //   });
  // }

  // static update(id: string, email: string) {
  //   return prisma.test.update({
  //     where: { id },
  //     data: { email },
  //   });
  // }

  // static delete(id: string) {
  //   return prisma.test.delete({
  //     where: { id },
  //   });
  // }
}
