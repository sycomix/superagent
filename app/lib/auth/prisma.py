from datetime import datetime, timedelta, timezone
from typing import Dict

import bcrypt
import jwt
from decouple import config
from fastapi import HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.lib.prisma import prisma

jwtSecret = config("JWT_SECRET")


def signJWT(user_id: str) -> Dict[str, str]:
    EXPIRES = datetime.now(tz=timezone.utc) + timedelta(days=365)

    payload = {
        "exp": EXPIRES,
        "userId": user_id,
    }
    return jwt.encode(payload, jwtSecret, algorithm="HS256")


def decodeJWT(token: str) -> dict:
    try:
        decoded = jwt.decode(token, jwtSecret, algorithms=["HS256"])
        return decoded if decoded["exp"] else None

    except jwt.ExpiredSignatureError:
        print("Token expired. Get new one")
        return None

    except Exception:
        return None


def encryptPassword(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def validatePassword(password: str, encrypted: str) -> str:
    return bcrypt.checkpw(password.encode("utf-8"), encrypted.encode("utf-8"))


class JWTBearer(HTTPBearer):
    def __init__(self, auto_error: bool = True):
        super(JWTBearer, self).__init__(auto_error=auto_error)

    async def __call__(self, request: Request):
        credentials: HTTPAuthorizationCredentials = await super(
            JWTBearer, self
        ).__call__(request)

        if not credentials:
            raise HTTPException(status_code=403, detail="Invalid authorization code.")
        if credentials.scheme != "Bearer":
            raise HTTPException(
                status_code=403, detail="Invalid token or expired token."
            )

        if not self.verify_jwt(credentials.credentials):
            if tokens_data := prisma.apitoken.find_first(
                where={"token": credentials.credentials}
            ):
                return signJWT(tokens_data.userId)

            else:
                raise HTTPException(
                    status_code=403, detail="Invalid token or expired token."
                )

        return credentials.credentials

    def verify_jwt(self, jwtToken: str) -> bool:
        try:
            payload = decodeJWT(jwtToken)

        except Exception:
            payload = None

        return bool(payload)
