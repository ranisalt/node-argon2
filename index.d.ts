// Type definitions for argon2 v0.14.0

/// <reference types="node" />

export interface Options {
    hashLength?: number;
    timeCost?: number;
    memoryCost?: number;
    parallelism?: number;
    type?: number;
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

export const argon2d: number;
export const argon2i: number;
export const argon2id: number;

export const defaults: Options;
export const limits: OptionLimits;
export function hash(plain: Buffer | string, salt: Buffer, options?: Options): Promise<string>;
export function generateSalt(length?: number): Promise<Buffer>;
export function verify(hash: string, plain: Buffer | string): Promise<boolean>;
