// Type definitions for argon2 v0.19.2

/// <reference types="node" />

export const argon2d: 0;
export const argon2i: 1;
export const argon2id: 2;

export interface Options {
  hashLength?: number;
  timeCost?: number;
  memoryCost?: number;
  parallelism?: number;
  type?: typeof argon2d | typeof argon2i | typeof argon2id;
  version?: number;
  salt?: Buffer;
  saltLength?: number;
  raw?: boolean;
  secret?: Buffer;
  associatedData?: Buffer;
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
export function hash(
  plain: Buffer | string,
  options: Options & { raw: true }
): Promise<Buffer>;
export function hash(
  plain: Buffer | string,
  options?: Options & { raw?: false }
): Promise<string>;
export function verify(
  hash: string,
  plain: Buffer | string,
  options?: Options
): Promise<boolean>;
export function needsRehash(hash: string, options?: Options): boolean;
