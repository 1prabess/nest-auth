import { CookieOptions, Response } from 'express';
import { fifteenMinutesFromNow, thirtyDaysFromNow } from './dates';

type AuthCookiesParams = {
  response: Response;
  refreshToken: string;
  accessToken: string;
};

const secure = process.env.NODE_ENV === 'production';

const defaultCookieOptions: CookieOptions = {
  sameSite: true,
  httpOnly: true,
  secure,
};

export const getRefreshTokenCookieOption = () => ({
  ...defaultCookieOptions,
  expires: thirtyDaysFromNow(),
  path: '/auth/refresh',
});

export const getAccessTokenCookieOption = () => ({
  ...defaultCookieOptions,
  expires: fifteenMinutesFromNow(),
  path: '/',
});

export const setAuthCookies = ({
  response,
  refreshToken,
  accessToken,
}: AuthCookiesParams) => {
  return response
    .cookie('refreshToken', refreshToken, getRefreshTokenCookieOption())
    .cookie('accessToken', accessToken, getAccessTokenCookieOption());
};

export const clearAuthCookies = (response: Response) => {
  return response.clearCookie('accessToken').clearCookie('refreshToken', {
    path: '/auth/refresh',
  });
};
