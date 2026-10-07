from fastapi import Depends, FastAPI

from app.routers import admin, items
from .deps import get_db

app = FastAPI(title="shop")


@app.get("/health")
def health():
    return {"ok": True}


@app.post("/api/upload")  # expect: endpoint/fastapi-unprotected-route
async def upload(db=Depends(get_db)):
    return {"uploaded": True}


app.include_router(items.router, prefix="/api")
app.include_router(admin.router)
