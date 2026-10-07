from fastapi import APIRouter, Depends

from ..deps import get_db

router = APIRouter(prefix="/admin")


@router.api_route("/stats", methods=["GET", "POST"])  # expect: endpoint/fastapi-unprotected-route
def stats(db=Depends(get_db)):
    return {"users": 10}
