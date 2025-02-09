import { Request, Response, NextFunction } from "express";
import { sendError } from "../helpers/sendErrors";

const requireUser = (req: Request, res: Response, next: NextFunction) => {
  const user = res.locals.user;

  if (!user) {
    return sendError(res, 403, "Access denied. No user found.");
  }

  return next();
};

export default requireUser;
