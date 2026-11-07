const SECONDS_PER_UNIT: Record<string, number> = {
  s: 1,
  m: 60,
  h: 3600,
  d: 86400,
};

export const parseDurationToSeconds = (value: string): number => {
  const match = /^(\d+)([smhd])$/.exec(value.trim());

  if (!match) {
    throw new Error(
      `Invalid duration "${value}". Expected a number followed by s, m, h, or d.`,
    );
  }

  return Number(match[1]) * (SECONDS_PER_UNIT[match[2]] ?? 1);
};
