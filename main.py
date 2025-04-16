from typing import Annotated
from datetime import timedelta
from fastapi import Depends, APIRouter, HTTPException, FastAPI
from core.auth import get_current_user, authenticate_user, create_access_token, bcrypt_context
from fastapi.security import OAuth2PasswordRequestForm
from database import SessionLocal, engine
from sqlalchemy.orm import Session
from models.user import User
from schemas.user import CreateUserRequest, Token
from starlette import status
from models import user

user.Base.metadata.create_all(bind=engine)
app = FastAPI()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


db_dependency = Annotated[Session, Depends(get_db)]
user_dependency = Annotated[dict, Depends(get_current_user)]

router = APIRouter(
    prefix="/auth",
    tags=["auth"]
)


@router.post("/", status_code=status.HTTP_201_CREATED)
async def create_user(db: db_dependency, create_user_request: CreateUserRequest):
    create_user_model = User(
        username=create_user_request.username,
        password=bcrypt_context.hash(create_user_request.password),
    )

    db.add(create_user_model)
    db.commit()


@router.post("/token")
async def login_for_access_token(form_data: Annotated[OAuth2PasswordRequestForm, Depends()], db: db_dependency):
    user = authenticate_user(form_data.username, form_data.password, db)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Could not validate user.")
    token = create_access_token(user.username, user.id, timedelta(minutes=20))
    return {"access_token": token, "token_type": "Bearer"}


@router.get("/user", status_code=status.HTTP_200_OK)
async def user(user: user_dependency, db: db_dependency):
    if user is None:
        raise HTTPException(status_code=401, detail="Authentication Failed")
    return {"User": user}


app.include_router(router)
