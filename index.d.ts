// Type definitions for argon2 v0.14.0
// Dependencies: TypeScript 2.0+
// Definitions by: JD Conley <https://github.com/jdconley/>
//
// Recommended Usage:
//
// import * as argon2 from "argon2";
//
// const hash = await argon2.hash(...);

export interface Options {
    hashLength?: number;
    timeCost?: number; 
    memoryCost?: number; 
    parallelism?: number; 
    argon2d?: boolean; 
}

export interface NumericLimit {
    max: number;
    min: number;
}

export interface OptionLimits {
    hashLength: NumericLimit;
    memoryCost: NumericLimit;
    timeCost: NumericLimit;
    parallelism: NumericLimit;
}

export const defaults: Options;
export const limits: OptionLimits;
export function hash(plain: Buffer | string, salt: Buffer, options?: Options): Promise<string>;
export function generateSalt(length: number): Promise<Buffer>;
export function verify(hash: string, plain: Buffer | string): Promise<boolean>;