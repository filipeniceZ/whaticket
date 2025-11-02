import { verify } from "jsonwebtoken";
import { Request, Response, NextFunction } from "express";
import { logger } from "../utils/logger";
import AppError from "../errors/AppError";
import authConfig from "../config/auth";
import User from "../models/User";
import { decrypt } from "../authCrypt";

const cache: Map<string, {
  user: any,
  timestamp: number
}> = new Map();

export async function fetchUserData(userId: string) {
  if (cache.has(userId)) {
    const cachedData = cache.get(userId);
    if (cachedData && (Date.now() - cachedData.timestamp) < 5 * 60 * 1000) { // 5 minutes cache
      return cachedData.user;
    }
  }

  try {
    const plainId = Number(await decrypt(userId));
    if (isNaN(plainId)) {
      return null;
    }

    const user = {
      id: plainId
    };

    cache.set(userId, { user, timestamp: Date.now() });

    return user;
  }
  catch {
    return null;
  }
}

const isAuth = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
  const solvingUserId = req.headers['authorization'] as string;
  if (!solvingUserId) {
    throw new AppError("ERR_SESSION_EXPIRED", 401);
  }

  const userData = await fetchUserData(solvingUserId);
  if (!userData) {
    logger.error(`No user data found for ID: ${solvingUserId}`);
    throw new AppError("ERR_SESSION_EXPIRED", 401);
  }

  if (userData.blocked) {
    logger.error(`User ID ${solvingUserId} is blocked.`);
    throw new AppError("ERR_USER_BLOCKED", 403);
  }

  const systemUser = await User.findOne({
    where: {
      id: userData.id,
    }
  });

  if (!systemUser) {
    logger.error(`No user found with email: ${userData.email}`);
    throw new AppError("ERR_USER_NOT_FOUND", 404);
  }

  req.user = {
    id: String(systemUser.id),
    profile: systemUser.profile,
    companyId: systemUser.companyId
  };

  // const [, token] = solvingUserId.split(" ");

  // try {
  //   const decoded = verify(token, authConfig.secret);
  //   const { id, profile, companyId } = decoded as TokenPayload;
  //   req.user = {
  //     id,
  //     profile,
  //     companyId
  //   };
  // } catch (err) {
  //   console.error(err);
  //   throw new AppError("Invalid token. We'll try to assign a new one on next request", 403 );
  // }

  return next();
};

export default isAuth;
