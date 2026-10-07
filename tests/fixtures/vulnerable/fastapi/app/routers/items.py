from fastapi import APIRouter

router = APIRouter(prefix="/items", tags=["items"])


@router.get("/")  # expect: endpoint/fastapi-unprotected-route
async def list_items():
    return []


@router.delete("/{item_id}")  # expect: endpoint/fastapi-unprotected-route
async def delete_item(item_id: int):
    return None
