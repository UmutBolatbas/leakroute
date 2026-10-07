from typing import Annotated

from fastapi import Depends, FastAPI, HTTPException, Request, Security, status
from fastapi.security import HTTPBearer, OAuth2PasswordBearer

from .auth import get_current_user, require_admin
from .routers import internal, orders

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
bearer = HTTPBearer()
CurrentUser = Annotated[dict, Depends(get_current_user)]

app = FastAPI()


@app.get("/health")
def health():
    return {"ok": True}


@app.post("/token")
def issue_token():
    return {"access_token": "issued"}


@app.get("/me")
def me(user: CurrentUser):
    return user


@app.post("/notes")
def create_note(token: Annotated[str, Depends(oauth2_scheme)]):
    return {}


@app.delete("/notes/{note_id}")
def delete_note(note_id: int, user=Depends(get_current_user)):
    return None


@app.put("/settings", dependencies=[Depends(require_admin)])
def settings():
    return {}


@app.get("/billing")
def billing(credentials=Security(bearer)):
    return {}


@app.get("/profile")
def profile(request: Request):
    if not request.session.get("user"):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)
    return request.session["user"]


app.include_router(orders.router, prefix="/orders", dependencies=[Depends(get_current_user)])
app.include_router(internal.router)
