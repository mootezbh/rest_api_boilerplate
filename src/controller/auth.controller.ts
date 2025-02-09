import { DocumentType } from "@typegoose/typegoose";
import { Request, Response } from "express";
import { get } from "lodash";
import { User } from "../model/user.model";
import { CreateSessionInput } from "../schema/auth.schema";
import {
  findSessionById,
  signAccessToken,
  signRefreshToken,
} from "../service/auth.service";
import { findUserByEmail, findUserById } from "../service/user.service";
import { verifyJwt } from "../utils/jwt";

export async function createSessionHandler(
  req: Request<{}, {}, { email: string; password: string }>,
  res: Response
): Promise<void> {
  const message = "Invalid email or password";
  const { email, password } = req.body;

  const user = await findUserByEmail(email);

  if (!user) {
    res.send(message);
    return;
  }

  if (!user.verified) {
    res.send("Please verify your email");
    return;
  }

  const isValid = await user.validatePassword(password);

  if (!isValid) {
    res.send(message);
    return;
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
}

export async function refreshAccessTokenHandler(
  req: Request,
  res: Response
): Promise<void> {
  const refreshToken = get(req, "headers.x-refresh") as string;

  const decoded = verifyJwt<{ session: string }>(
    refreshToken,
    "refreshTokenPublicKey"
  );

  if (!decoded) {
    res.status(401).send("Could not refresh access token");
    return;
  }

  const session = await findSessionById(decoded.session);

  if (!session || !session.valid) {
    res.status(401).send("Could not refresh access token");
    return;
  }

  const user = await findUserById(String(session.user));

  if (!user) {
    res.status(401).send("Could not refresh access token");
    return;
  }

  const accessToken = signAccessToken(user);

  res.send({ accessToken });
  return;
}
