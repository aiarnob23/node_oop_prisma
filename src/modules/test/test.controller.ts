import { Request, Response } from "express";
import { TestService } from "./test.service";
import { BaseController } from "@/core/BaseController";

export class TestController extends BaseController{
  constructor(private testService:TestService){
    super();
  }


  // create new test
  public createTest = async(req:Request, res:Response)=>{
    const body = req.body;
    
    const result = await this.testService.createTest(body);

    return this.sendCreatedResponse(
      res,
      result,
      "Employee created successfully"
    )
  }



  // static async create(req: Request, res: Response) {
  //   const { email } = req.body;
  //   if (!email) return res.status(400).json({ message: "email required" });

  //   const data = await TestService.createTest(email);
  //   res.status(201).json(data);
  // }

  // static async findAll(_req: Request, res: Response) {
  //   const data = await TestService.findAll();
  //   res.json(data);
  // }

  // static async findOne(req: Request, res: Response) {
  //   const { id } = req.params;

  //   const data = await TestService.findById(id);
  //   if (!data) return res.status(404).json({ message: "not found" });

  //   res.json(data);
  // }

  // static async update(req: Request, res: Response) {
  //   const { id } = req.params;
  //   const { email } = req.body;

  //   const data = await TestService.update(id, email);
  //   res.json(data);
  // }

  // static async remove(req: Request, res: Response) {
  //   const { id } = req.params;

  //   await TestService.delete(id);
  //   res.status(204).send();
  // }
}
