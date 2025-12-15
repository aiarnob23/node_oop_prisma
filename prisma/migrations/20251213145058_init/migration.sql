-- CreateTable
CREATE TABLE "test" (
    "email" TEXT NOT NULL
);

-- CreateIndex
CREATE UNIQUE INDEX "test_email_key" ON "test"("email");
