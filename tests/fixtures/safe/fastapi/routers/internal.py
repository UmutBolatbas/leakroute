import os

from fastapi import APIRouter, Depends, Header, HTTPException


def check_service_key(x_service_key: str = Header()):
    if x_service_key != os.environ["SERVICE_KEY"]:
        raise HTTPException(status_code=403)


router = APIRouter(prefix="/internal", dependencies=[Depends(check_service_key)])


@router.post("/reindex")
def reindex():
    return {}
