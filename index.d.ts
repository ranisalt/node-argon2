// Type definitions for argon2 v0.14.0

/// <reference types="node" />

export interface IOptions {
    hashLength?: number;
    timeCost?: number;
    memoryCost?: number;
    parallelism?: number;
    type?: 0 | 1 | 2;
    raw?: boolean;
    saltGeneratorF?: (size: number, callback: (err: Error, buf: Buffer) => void) => void;
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

export const argon2d: 0;
export const argon2i: 1;
export const argon2id: 2;

export const defaults: IOptions;
export const limits: IOptionLimits;
export function hash(plain: Buffer | string, options?: IOptions): Promise<string>;
export function verify(hash: string, plain: Buffer | string): Promise<boolean>;
