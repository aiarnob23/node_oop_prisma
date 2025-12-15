import { stringToNumber } from "@/utils/stringToNumber";
import { z } from "zod";

export const TestValidation = {
  //
  // ✅ Params
  //
  params: {
    id: z.object({
      id: z.string().uuid("Invalid test ID"),
    }),
  },

  //
  // ✅ Query
  //
  query: {
    list: z.object({
      page: z.preprocess(
        (val) => stringToNumber(val) || 1,
        z.number().int().min(1).default(1)
      ),
      limit: z.preprocess(
        (val) => {
          const num = stringToNumber(val) || 10;
          return Math.min(Math.max(num, 1), 100);
        },
        z.number().int().min(1).max(100).default(10)
      ),
      search: z.string().optional(),
      sortOrder: z.enum(["asc", "desc"]).default("desc"),
    }),
  },

  //
  // ✅ Body
  //
  body: {
    create: z
      .object({
        email: z.string().email("Invalid email"),
      })
      .strict(),

    update: z
      .object({
        email: z.string().email().optional(),
        isDeleted: z.boolean().optional(),
      })
      .strict()
      .refine((data) => Object.keys(data).length > 0, {
        message: "At least one field must be provided",
      }),
  },
};

// ---------------------------------------------
// ✅ Types (DTOs)
// ---------------------------------------------
export type TestIdParams = z.infer<typeof TestValidation.params.id>;
export type TestListQuery = z.infer<typeof TestValidation.query.list>;
export type CreateTestInput = z.infer<typeof TestValidation.body.create>;
export type UpdateTestInput = z.infer<typeof TestValidation.body.update>;
