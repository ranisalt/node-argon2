// Type definitions for argon2 v0.14.0
// Dependencies: TypeScript 2.0+
// Definitions by: JD Conley <https://github.com/jdconley/>
//
// Recommended Usage:
//
// import * as argon2 from "argon2";
//
// const hash = await argon2.hash(...);

export interface IOptions {
    hashLength?: number;
    timeCost?: number; 
    memoryCost?: number; 
    parallelism?: number; 
    argon2d?: boolean; 
}

export interface INumericLimit {
    max: number;
    min: number;
}

export interface IOptionLimits {
    hashLength: INumericLimit;
    memoryCost: INumericLimit;
    timeCost: INumericLimit;
    parallelism: INumericLimit;
}

export const defaults: IOptions;
export const limits: IOptionLimits;
export function hash(plain: string, salt: Buffer | string, options?: IOptions): Promise<string>;
export function generateSalt(length: number): Promise<Buffer>;
export function verify(hash: string, plain: string): Promise<boolean>;