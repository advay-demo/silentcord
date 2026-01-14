import { Request, Response, NextFunction } from "express";

type IPInfo = {
  count: number;
  startTime: number;
};

const ipData: Record<string, IPInfo> = {};

const LIMIT = 100;       // max requests
const WINDOW = 60_000;   // 1 minute

export default function ratelimiter(req: Request, res: Response, next: NextFunction) {
    const ip = req.ip || "unknown";
    const now = Date.now();
    if (!ipData[ip]) {
        ipData[ip] = { count: 1, startTime: now };
        return next();
    }
    const info = ipData[ip];
    if (now - info.startTime > WINDOW) {
        info.count = 1;
        info.startTime = now;
        return next();
    }
    info.count++;
    if (info.count > LIMIT) {
        return res.status(429).json({
            error: true,
            message: "Too many requests. Please slow down."
         });
        }
        next();
    }