export const redisConfig = {
  revokedAccessToken: {
    key: (jti: string) => `nest-auth:revoked:jti:${jti}`,
    ttl: 15 * 60,
  },
} as const;
