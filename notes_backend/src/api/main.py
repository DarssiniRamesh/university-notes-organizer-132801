# ===============================================================
# FastAPI entrypoint for the notes_backend container
# The FastAPI app instance declared as "app" below is the object
# that should be imported via uvicorn as:
#   uvicorn src.api.main:app
# Ensure the above import path is used in your launch command.
# ===============================================================
from datetime import datetime, timedelta
from typing import List, Optional

from fastapi import FastAPI, Depends, HTTPException, status, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.responses import JSONResponse
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel, Field
from sqlalchemy import (Column, Integer, String, DateTime, Text, ForeignKey,
                        create_engine, Table)
from sqlalchemy.orm import declarative_base, sessionmaker, relationship, Session

# =================== Settings ====================
DATABASE_URL = "sqlite:///./notes_app.db"
SECRET_KEY = "supersecretkey"  # TODO: Replace for production
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 8
API_PORT = 3001

# ================ Database Setup ===================
Base = declarative_base()
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# ========== Association Tables for Many-to-many ==========
note_category_table = Table(
    "note_category", Base.metadata,
    Column("note_id", ForeignKey("notes.id"), primary_key=True),
    Column("category_id", ForeignKey("categories.id"), primary_key=True)
)

note_tag_table = Table(
    "note_tag", Base.metadata,
    Column("note_id", ForeignKey("notes.id"), primary_key=True),
    Column("tag_id", ForeignKey("tags.id"), primary_key=True)
)

# ================== Models ========================

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(32), unique=True, index=True, nullable=False)
    hashed_password = Column(String(128), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    notes = relationship("Note", back_populates="owner", cascade="all, delete")

class Note(Base):
    __tablename__ = "notes"
    id = Column(Integer, primary_key=True, index=True)
    content = Column(Text, nullable=False)
    title = Column(String(128), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow)
    user_id = Column(Integer, ForeignKey("users.id"))
    owner = relationship("User", back_populates="notes")
    categories = relationship("Category", secondary=note_category_table, back_populates="notes")
    tags = relationship("Tag", secondary=note_tag_table, back_populates="notes")

class Category(Base):
    __tablename__ = "categories"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(64), unique=True, index=True)
    notes = relationship("Note", secondary=note_category_table, back_populates="categories")

class Tag(Base):
    __tablename__ = "tags"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(64), unique=True, index=True)
    notes = relationship("Note", secondary=note_tag_table, back_populates="tags")

# =================== Schemas (Pydantic) ====================

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: Optional[str] = None

class UserBase(BaseModel):
    username: str = Field(..., description="Unique username for the user.")

class UserCreate(UserBase):
    password: str = Field(..., description="Password for the user.")

class UserOut(UserBase):
    id: int
    created_at: datetime

    class Config:
        orm_mode = True

class CategoryBase(BaseModel):
    name: str = Field(..., description="Category name.")

class CategoryCreate(CategoryBase):
    pass

class CategoryOut(CategoryBase):
    id: int

    class Config:
        orm_mode = True

class TagBase(BaseModel):
    name: str = Field(..., description="Tag name.")

class TagCreate(TagBase):
    pass

class TagOut(TagBase):
    id: int

    class Config:
        orm_mode = True

class NoteBase(BaseModel):
    title: str = Field(..., description="Title of the note.")
    content: str = Field(..., description="Note content.")
    category_ids: Optional[List[int]] = Field(default=[], description="IDs of categories.")
    tag_ids: Optional[List[int]] = Field(default=[], description="IDs of tags.")

class NoteCreate(NoteBase):
    pass

class NoteUpdate(NoteBase):
    pass

class NoteOut(NoteBase):
    id: int
    created_at: datetime
    updated_at: datetime
    categories: List[CategoryOut] = []
    tags: List[TagOut] = []

    class Config:
        orm_mode = True

# ============= Password & Auth Utilities ==============

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/token")

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta if expires_delta else timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# ================= Dependency ======================
# PUBLIC_INTERFACE
def get_db():
    """Dependency that yields a database session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# ================= User CRUD ======================
# PUBLIC_INTERFACE
def get_user_by_username(db: Session, username: str) -> Optional[User]:
    """Fetch a user by username."""
    return db.query(User).filter(User.username == username).first()

# PUBLIC_INTERFACE
def authenticate_user(db: Session, username: str, password: str) -> Optional[User]:
    """Authenticate user with username and password."""
    user = get_user_by_username(db, username)
    if not user or not verify_password(password, user.hashed_password):
        return None
    return user

# PUBLIC_INTERFACE
def get_current_user(db: Session = Depends(get_db), token: str = Depends(oauth2_scheme)) -> User:
    """Get current user based on provided JWT token."""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception
    user = get_user_by_username(db, token_data.username)
    if user is None:
        raise credentials_exception
    return user

# ================= FastAPI App Def ==================
"""Module entrypoint for FastAPI notes backend.
The ASGI app is defined below as 'app' and should be loaded with:
    uvicorn src.api.main:app
"""
app = FastAPI(
    title="University Notes API",
    description="RESTful backend for student notes with authentication, note CRUD, categories, and tags.",
    version="1.0.0",
    docs_url="/docs",
    openapi_url="/openapi.json"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Adjust for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ================== Event Handlers =====================
@app.on_event("startup")
def startup():
    Base.metadata.create_all(bind=engine)  # Auto-initialize SQLite DB

# ================= Error Handling ===================
@app.exception_handler(Exception)
def generic_exception_handler(request: Request, exc: Exception):
    return JSONResponse(
        status_code=500,
        content={"detail": str(exc)},
    )

# ================== Auth API =======================

@app.post("/auth/signup", response_model=UserOut, summary="Sign up a new user", tags=["Authentication"])
# PUBLIC_INTERFACE
def signup(user_in: UserCreate, db: Session = Depends(get_db)):
    """Create a new user account."""
    if get_user_by_username(db, user_in.username):
        raise HTTPException(status_code=400, detail="Username already taken")
    hashed_pw = get_password_hash(user_in.password)
    new_user = User(username=user_in.username, hashed_password=hashed_pw)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return new_user

@app.post("/auth/token", response_model=Token, summary="Get auth token", tags=["Authentication"])
# PUBLIC_INTERFACE
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    """Login and get access token."""
    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    access_token = create_access_token(data={"sub": user.username})
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/auth/me", response_model=UserOut, summary="Get current user", tags=["Authentication"])
# PUBLIC_INTERFACE
def get_me(current_user: User = Depends(get_current_user)):
    """Get the details of the current logged-in user."""
    return current_user

# ================== Notes CRUD API ========================

@app.post("/notes/", response_model=NoteOut, summary="Create a new note", tags=["Notes"])
# PUBLIC_INTERFACE
def create_note(note: NoteCreate, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    """Create a new note for the current user."""
    note_obj = Note(
        title=note.title,
        content=note.content,
        owner=current_user,
        created_at=datetime.utcnow(),
        updated_at=datetime.utcnow()
    )
    if note.category_ids:
        note_obj.categories = db.query(Category).filter(Category.id.in_(note.category_ids)).all()
    if note.tag_ids:
        note_obj.tags = db.query(Tag).filter(Tag.id.in_(note.tag_ids)).all()
    db.add(note_obj)
    db.commit()
    db.refresh(note_obj)
    return note_obj

@app.get("/notes/", response_model=List[NoteOut], summary="List all notes (owned by user)", tags=["Notes"])
# PUBLIC_INTERFACE
def list_notes(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    """List all notes for the current user."""
    notes = db.query(Note).filter(Note.owner == current_user).all()
    return notes

@app.get("/notes/{note_id}", response_model=NoteOut, summary="Get a note by its ID", tags=["Notes"])
# PUBLIC_INTERFACE
def get_note(note_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    """Retrieve note by note_id (for the current user)."""
    note = db.query(Note).filter(Note.id == note_id, Note.owner == current_user).first()
    if note is None:
        raise HTTPException(status_code=404, detail="Note not found")
    return note

@app.put("/notes/{note_id}", response_model=NoteOut, summary="Update a note", tags=["Notes"])
# PUBLIC_INTERFACE
def update_note(note_id: int, note: NoteUpdate, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    """Update a note. Only the owner can update."""
    note_obj = db.query(Note).filter(Note.id == note_id, Note.owner == current_user).first()
    if not note_obj:
        raise HTTPException(status_code=404, detail="Note not found")
    note_obj.title = note.title
    note_obj.content = note.content
    note_obj.updated_at = datetime.utcnow()
    if note.category_ids is not None:
        note_obj.categories = db.query(Category).filter(Category.id.in_(note.category_ids)).all()
    if note.tag_ids is not None:
        note_obj.tags = db.query(Tag).filter(Tag.id.in_(note.tag_ids)).all()
    db.commit()
    db.refresh(note_obj)
    return note_obj

@app.delete("/notes/{note_id}", status_code=204, summary="Delete a note", tags=["Notes"])
# PUBLIC_INTERFACE
def delete_note(note_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    """Delete a note. Only the owner can delete."""
    note = db.query(Note).filter(Note.id == note_id, Note.owner == current_user).first()
    if not note:
        raise HTTPException(status_code=404, detail="Note not found")
    db.delete(note)
    db.commit()
    return

# ==================== Category REST =======================

@app.post("/categories/", response_model=CategoryOut, summary="Create category", tags=["Categories"])
# PUBLIC_INTERFACE
def create_category(cat: CategoryCreate, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    """Create a new category."""
    existing = db.query(Category).filter(Category.name == cat.name).first()
    if existing:
        raise HTTPException(status_code=400, detail="Category already exists")
    new_cat = Category(name=cat.name)
    db.add(new_cat)
    db.commit()
    db.refresh(new_cat)
    return new_cat

@app.get("/categories/", response_model=List[CategoryOut], summary="List categories", tags=["Categories"])
# PUBLIC_INTERFACE
def list_categories(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    """List all categories."""
    categories = db.query(Category).all()
    return categories

@app.delete("/categories/{cat_id}", status_code=204, summary="Delete category", tags=["Categories"])
# PUBLIC_INTERFACE
def delete_category(cat_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    """Delete category by ID."""
    category = db.query(Category).filter(Category.id == cat_id).first()
    if not category:
        raise HTTPException(status_code=404, detail="Category not found")
    db.delete(category)
    db.commit()
    return

# ==================== Tag REST =======================

@app.post("/tags/", response_model=TagOut, summary="Create tag", tags=["Tags"])
# PUBLIC_INTERFACE
def create_tag(tag: TagCreate, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    """Create a new tag."""
    existing = db.query(Tag).filter(Tag.name == tag.name).first()
    if existing:
        raise HTTPException(status_code=400, detail="Tag already exists")
    new_tag = Tag(name=tag.name)
    db.add(new_tag)
    db.commit()
    db.refresh(new_tag)
    return new_tag

@app.get("/tags/", response_model=List[TagOut], summary="List tags", tags=["Tags"])
# PUBLIC_INTERFACE
def list_tags(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    """List all tags."""
    tags = db.query(Tag).all()
    return tags

@app.delete("/tags/{tag_id}", status_code=204, summary="Delete tag", tags=["Tags"])
# PUBLIC_INTERFACE
def delete_tag(tag_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    """Delete tag by ID."""
    tag = db.query(Tag).filter(Tag.id == tag_id).first()
    if not tag:
        raise HTTPException(status_code=404, detail="Tag not found")
    db.delete(tag)
    db.commit()
    return

# ================== Health ========================

@app.get("/", summary="Health Check", tags=["Utility"])
def health_check():
    """Health check endpoint."""
    return {"message": "Healthy"}

# ================== Run with Uvicorn (Optional) ===============
# This enables running: python src/api/main.py for development/demo only!

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=API_PORT)
