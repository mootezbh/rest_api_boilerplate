import { RequestHandler } from "express";
import { get } from "lodash";
import { CreateSessionInput } from "../schema/auth.schema";
import {
  findSessionById,
  signAccessToken,
  signRefreshToken,
} from "../service/auth.service";
import { findUserByEmail, findUserById } from "../service/user.service";
import { verifyJwt } from "../utils/jwt";
import { sendError } from "../helpers/sendErrors";

export const createSessionHandler: RequestHandler<
  {},
  {},
  CreateSessionInput
> = async (req, res) => {
  const message = "Invalid email or password";
  const { email, password } = req.body;

  const user = await findUserByEmail(email);

  if (!user) {
    return sendError(res, 400, message);
  }

  if (!user.verified) {
    return sendError(res, 400, "Please verify your email");
  }

  const isValid = await user.validatePassword(password);

  if (!isValid) {
    return sendError(res, 400, message);
  }

  // sign a access token
  const accessToken = signAccessToken(user);

  // sign a refresh token
  const refreshToken = await signRefreshToken({ userId: user._id.toString() });

  // send the tokens
  res.send({
    accessToken,
    refreshToken,
  });
};

export const refreshAccessTokenHandler: RequestHandler = async (req, res) => {
  const refreshToken = get(req, "headers.x-refresh") as string;

  const decoded = verifyJwt<{ session: string }>(
    refreshToken,
    "refreshTokenPublicKey"
  );

  if (!decoded) {
    return sendError(res, 401, "Could not refresh access token");
  }

  const session = await findSessionById(decoded.session);

  if (!session || !session.valid) {
    return sendError(res, 401, "Could not refresh access token");
  }

  const user = await findUserById(String(session.user));

  if (!user) {
    return sendError(res, 401, "Could not refresh access token");
  }

  const accessToken = signAccessToken(user);
  res.send({ accessToken });
};
