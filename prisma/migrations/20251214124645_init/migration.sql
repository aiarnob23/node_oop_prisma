/*
  Warnings:

  - Added the required column `password` to the `Arnob` table without a default value. This is not possible if the table is not empty.

*/
-- AlterTable
ALTER TABLE "Arnob" ADD COLUMN     "password" TEXT NOT NULL;
