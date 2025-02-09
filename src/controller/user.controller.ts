import { RequestHandler } from "express";
import { nanoid } from "nanoid";
import { sendError } from "../helpers/sendErrors";
import {
  CreateUserInput,
  ForgotPasswordInput,
  ResetPasswordInput,
  VerifyUserInput,
} from "../schema/user.schema";
import {
  createUser,
  findUserByEmail,
  findUserById,
} from "../service/user.service";
import log from "../utils/logger";
import sendEmail from "../utils/mailer";

export const createUserHandler: RequestHandler<
  {},
  {},
  CreateUserInput
> = async (req, res) => {
  const body = req.body;

  try {
    const user = await createUser(body);

    await sendEmail({
      to: user.email,
      from: "test@example.com",
      subject: "Verify your email",
      text: `verification code: ${user.verificationCode}. Id: ${user._id}`,
    });

    res.send("User successfully created");
  } catch (e: any) {
    if (e.code === 11000) {
      return sendError(res, 409, "Account already exists");
    }
    return sendError(res, 500, e.message);
  }
};

export const verifyUserHandler: RequestHandler<VerifyUserInput> = async (
  req,
  res
) => {
  const id = req.params.id;
  const verificationCode = req.params.verificationCode;

  const user = await findUserById(id);

  if (!user) {
    return sendError(res, 404, "Could not verify user");
  }

  if (user.verified) {
    return sendError(res, 400, "User is already verified");
  }

  if (user.verificationCode === verificationCode) {
    user.verified = true;
    await user.save();
    res.send("User successfully verified");
    return;
  }

  return sendError(res, 400, "Could not verify user");
};

export const forgotPasswordHandler: RequestHandler<
  {},
  {},
  ForgotPasswordInput
> = async (req, res) => {
  const message =
    "If a user with that email is registered you will receive a password reset email";

  const { email } = req.body;
  const user = await findUserByEmail(email);

  if (!user) {
    log.debug(`User with email ${email} does not exists`);
    res.send(message);
    return;
  }

  if (!user.verified) {
    return sendError(res, 400, "User is not verified");
  }

  const passwordResetCode = nanoid();
  user.passwordResetCode = passwordResetCode;
  await user.save();

  await sendEmail({
    to: user.email,
    from: "test@example.com",
    subject: "Reset your password",
    text: `Password reset code: ${passwordResetCode}. Id ${user._id}`,
  });

  log.debug(`Password reset email sent to ${email}`);
  res.send(message);
};

export const resetPasswordHandler: RequestHandler<
  ResetPasswordInput["params"],
  {},
  ResetPasswordInput["body"]
> = async (req, res) => {
  const { id, passwordResetCode } = req.params;
  const { password } = req.body;

  const user = await findUserById(id);

  if (
    !user ||
    !user.passwordResetCode ||
    user.passwordResetCode !== passwordResetCode
  ) {
    return sendError(res, 400, "Could not reset user password");
  }

  user.passwordResetCode = null;
  user.password = password;
  await user.save();

  res.send("Successfully updated password");
};

export const getCurrentUserHandler: RequestHandler = async (req, res) => {
  res.send(res.locals.user);
};
