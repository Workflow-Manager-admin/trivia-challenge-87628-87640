import os
import asyncio
from typing import List, Optional, Dict, Any
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Depends, HTTPException, status, Query
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, Field
from jose import JWTError, jwt
from passlib.context import CryptContext
from datetime import datetime, timedelta
import databases
import sqlalchemy

# ENV: You must define and provide these environment variables:
# QUIZ_DB_URL, JWT_SECRET_KEY, ACCESS_TOKEN_EXPIRE_MINUTES

DATABASE_URL = os.getenv("QUIZ_DB_URL", "sqlite:///./quiz.db")
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "secret")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "240"))
JWT_ALGORITHM = "HS256"

database = databases.Database(DATABASE_URL)
metadata = sqlalchemy.MetaData()

# Models/tables
users = sqlalchemy.Table(
    "users", metadata,
    sqlalchemy.Column("id", sqlalchemy.Integer, primary_key=True),
    sqlalchemy.Column("username", sqlalchemy.String, unique=True, index=True),
    sqlalchemy.Column("hashed_password", sqlalchemy.String),
)

categories = sqlalchemy.Table(
    "categories", metadata,
    sqlalchemy.Column("id", sqlalchemy.Integer, primary_key=True),
    sqlalchemy.Column("name", sqlalchemy.String, unique=True)
)

questions = sqlalchemy.Table(
    "questions", metadata,
    sqlalchemy.Column("id", sqlalchemy.Integer, primary_key=True),
    sqlalchemy.Column("category_id", sqlalchemy.Integer),
    sqlalchemy.Column("question", sqlalchemy.String),
    sqlalchemy.Column("choices", sqlalchemy.JSON),
    sqlalchemy.Column("answer", sqlalchemy.String),
)

leaderboard = sqlalchemy.Table(
    "leaderboard", metadata,
    sqlalchemy.Column("id", sqlalchemy.Integer, primary_key=True),
    sqlalchemy.Column("username", sqlalchemy.String),
    sqlalchemy.Column("score", sqlalchemy.Integer),
    sqlalchemy.Column("category_id", sqlalchemy.Integer),
    sqlalchemy.Column("created_at", sqlalchemy.DateTime, default=datetime.utcnow),
)

# For single player game results; multiplayer game state lives in memory/WS (not persisted)
results = sqlalchemy.Table(
    "results", metadata,
    sqlalchemy.Column("id", sqlalchemy.Integer, primary_key=True),
    sqlalchemy.Column("username", sqlalchemy.String),
    sqlalchemy.Column("category_id", sqlalchemy.Integer),
    sqlalchemy.Column("score", sqlalchemy.Integer),
    sqlalchemy.Column("max_score", sqlalchemy.Integer),
    sqlalchemy.Column("created_at", sqlalchemy.DateTime, default=datetime.utcnow),
)

engine = sqlalchemy.create_engine(DATABASE_URL)
metadata.create_all(engine)

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/token")

app = FastAPI(
    title="QuickQuiz API",
    description="Backend API for QuickQuiz: supports single/multiplayer trivia, authentication, leaderboard, and real-time gameplay.",
    version="1.0.0",
    openapi_tags=[
        {"name": "auth", "description": "User authentication"},
        {"name": "quiz", "description": "Game and question APIs"},
        {"name": "ws", "description": "Multiplayer websocket API"},
        {"name": "leaderboard", "description": "Leaderboards and results retrieval"},
    ]
)

origins = ["*"] # CORS for dev; restrict in prod!
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins, allow_credentials=True, allow_methods=["*"], allow_headers=["*"],
)

# ----------- UTILS -----------
def verify_password(plain, hashed):
    return pwd_context.verify(plain, hashed)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta]=None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)

async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    query = users.select().where(users.c.username == username)
    user = await database.fetch_one(query)
    if user is None:
        raise credentials_exception
    return dict(user)

# ----------- Pydantic MODELS -----------
class Token(BaseModel):
    access_token: str
    token_type: str

class UserIn(BaseModel):
    username: str = Field(..., min_length=3)
    password: str = Field(..., min_length=3)

class UserOut(BaseModel):
    username: str

class Category(BaseModel):
    id: int
    name: str

class QuestionOut(BaseModel):
    id: int
    question: str
    choices: List[str]
    category_id: int

class SubmitAnswerIn(BaseModel):
    question_id: int
    answer: str

class GameResultIn(BaseModel):
    category_id: int
    score: int
    max_score: int

class LeaderboardEntry(BaseModel):
    username: str
    score: int
    category_id: int
    created_at: datetime

class MultiplayerAction(BaseModel):
    action: str
    data: Optional[Dict[str, Any]]

# ----------- AUTH API -----------

# PUBLIC_INTERFACE
@app.post("/register", response_model=UserOut, tags=["auth"])
async def register(user_in: UserIn):
    """Register a new user."""
    query = users.select().where(users.c.username == user_in.username)
    user = await database.fetch_one(query)
    if user:
        raise HTTPException(status_code=400, detail="Username already registered")
    hashed_pass = get_password_hash(user_in.password)
    query = users.insert().values(username=user_in.username, hashed_password=hashed_pass)
    await database.execute(query)
    return {"username": user_in.username}

# PUBLIC_INTERFACE
@app.post("/token", response_model=Token, tags=["auth"])
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    """Get JWT access token via OAuth2."""
    query = users.select().where(users.c.username == form_data.username)
    user = await database.fetch_one(query)
    if not user or not verify_password(form_data.password, user["hashed_password"]):
        raise HTTPException(status_code=401, detail="Incorrect username or password")
    access_token = create_access_token(data={"sub": user["username"]})
    return {"access_token": access_token, "token_type": "bearer"}

# ----------- QUIZ GAME API -----------

# PUBLIC_INTERFACE
@app.get("/categories", response_model=List[Category], tags=["quiz"])
async def get_categories():
    """List all quiz categories."""
    query = categories.select()
    rows = await database.fetch_all(query)
    return [{"id": r["id"], "name": r["name"]} for r in rows]

# PUBLIC_INTERFACE
@app.get("/questions", response_model=List[QuestionOut], tags=["quiz"])
async def get_questions(category_id: int = Query(..., description="Category ID"), amount: int = 20):
    """Retrieve a random set of questions for a category (max 20)."""
    query = (
        questions.select()
        .where(questions.c.category_id == category_id)
        .order_by(sqlalchemy.func.random())
        .limit(amount)
    )
    rows = await database.fetch_all(query)
    return [
        {
            "id": r["id"],
            "question": r["question"],
            "choices": r["choices"],
            "category_id": r["category_id"],
        }
        for r in rows
    ]

# PUBLIC_INTERFACE
@app.post("/submit", tags=["quiz"])
async def submit_answers(
    answers: List[SubmitAnswerIn],
    category_id: int = Query(..., description="Category ID"),
    user: dict = Depends(get_current_user)
):
    """
    Submit answers for single player game session and store result.
    Returns score and max possible score.
    """
    if not answers:
        raise HTTPException(status_code=400, detail="No answers submitted")
    ids = [ans.question_id for ans in answers]
    db_q = questions.select().where(questions.c.id.in_(ids))
    qs = await database.fetch_all(db_q)
    correct = 0
    for ans in answers:
        q = next((q for q in qs if q["id"] == ans.question_id), None)
        if q and q["answer"].strip().lower() == ans.answer.strip().lower():
            correct += 1
    max_score = len(answers)
    # Store result
    ins = results.insert().values(
        username=user["username"],
        category_id=category_id,
        score=correct,
        max_score=max_score,
        created_at=datetime.utcnow(),
    )
    await database.execute(ins)
    # Optionally add to leaderboard if score qualifies
    lb = leaderboard.insert().values(
        username=user["username"],
        score=correct,
        category_id=category_id,
        created_at=datetime.utcnow(),
    )
    await database.execute(lb)
    return {"score": correct, "max_score": max_score}

# ----------- LEADERBOARD/RESULTS API -----------

# PUBLIC_INTERFACE
@app.get("/leaderboard/{category_id}", response_model=List[LeaderboardEntry], tags=["leaderboard"])
async def get_leaderboard(category_id: int, limit: int = 10):
    """
    Get the leaderboard for a category.
    """
    query = (
        leaderboard.select()
        .where(leaderboard.c.category_id == category_id)
        .order_by(leaderboard.c.score.desc())
        .limit(limit)
    )
    rows = await database.fetch_all(query)
    return [
        LeaderboardEntry(
            username=r["username"],
            score=r["score"],
            category_id=r["category_id"],
            created_at=r["created_at"],
        )
        for r in rows
    ]

# PUBLIC_INTERFACE
@app.get("/results", tags=["leaderboard"])
async def get_my_results(user: dict = Depends(get_current_user)):
    """Get previous quiz results for the current user."""
    query = results.select().where(results.c.username == user["username"]).order_by(results.c.created_at.desc())
    records = await database.fetch_all(query)
    return [
        {
            "score": r["score"],
            "max_score": r["max_score"],
            "category_id": r["category_id"],
            "created_at": r["created_at"],
        }
        for r in records
    ]

# ----------- MULTIPLAYER WEBSOCKET -------------

class ConnectionManager:
    """
    Manages multiplayer quiz rooms/sessions.
    """
    def __init__(self):
        self.active_connections: Dict[str, List[WebSocket]] = {} # room_id: websockets
        self.usernames_by_ws: Dict[WebSocket, str] = {}
        self.scores_by_room: Dict[str, Dict[str, int]] = {}
        self.questions_cache: Dict[str, List[Dict]] = {}

    async def connect(self, room_id: str, ws: WebSocket, username: str):
        await ws.accept()
        if room_id not in self.active_connections:
            self.active_connections[room_id] = []
            self.scores_by_room[room_id] = {}
        self.active_connections[room_id].append(ws)
        self.usernames_by_ws[ws] = username
        self.scores_by_room[room_id][username] = 0

    def disconnect(self, room_id: str, ws: WebSocket):
        if room_id in self.active_connections and ws in self.active_connections[room_id]:
            self.active_connections[room_id].remove(ws)
            username = self.usernames_by_ws.get(ws)
            if username and username in self.scores_by_room.get(room_id, {}):
                del self.scores_by_room[room_id][username]
            del self.usernames_by_ws[ws]

    async def broadcast(self, room_id: str, data: dict):
        for ws in self.active_connections.get(room_id, []):
            await ws.send_json(data)

    async def send_personal(self, ws: WebSocket, data: dict):
        await ws.send_json(data)

manager = ConnectionManager()

# PUBLIC_INTERFACE
@app.websocket("/ws/multiplayer/{room_id}")
async def websocket_endpoint(websocket: WebSocket, room_id: str, token: str):
    """
    WebSocket endpoint for multiplayer sessions.
    Real-time quiz gameplay, scoring, and chat per room.
    Params: room_id (str), token (JWT access token as query param)
    Send actions:
     - {action: "join", data: {category_id}}
     - {action: "answer", data: {question_id, answer}}
     - {action: "chat", data: {message}}
    Receives:
     - question, score update, chat message, leaderboard, game end, error, etc.
    """
    # Authenticate user
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        username: str = payload.get("sub")
        if not username:
            await websocket.close(code=1008)
            return
    except JWTError:
        await websocket.close(code=1008)
        return
    await manager.connect(room_id, websocket, username)
    try:
        while True:
            data = await websocket.receive_json()
            action = data.get("action")
            if action == "join":
                category_id = data["data"]["category_id"]
                # Fetch and cache questions for this room only once
                if room_id not in manager.questions_cache:
                    q_query = (
                        questions.select()
                        .where(questions.c.category_id == category_id)
                        .order_by(sqlalchemy.func.random())
                        .limit(20)
                    )
                    qs = await database.fetch_all(q_query)
                    manager.questions_cache[room_id] = [
                        {"id": q["id"], "question": q["question"], "choices": q["choices"]}
                        for q in qs
                    ]
                await manager.broadcast(room_id, {"type": "game_start", "questions": manager.questions_cache[room_id]})
            elif action == "answer":
                qid = data["data"]["question_id"]
                answer = data["data"]["answer"]
                cat_id = None
                # Validate answer
                q_query = questions.select().where(questions.c.id == qid)
                q = await database.fetch_one(q_query)
                if q:
                    cat_id = q["category_id"]
                    correct = (q["answer"].strip().lower() == answer.strip().lower())
                    if correct:
                        manager.scores_by_room[room_id][username] += 1
                # Broadcast updated scores
                await manager.broadcast(room_id, {
                    "type": "score_update",
                    "scores": manager.scores_by_room[room_id]
                })
            elif action == "chat":
                msg = data["data"]["message"]
                await manager.broadcast(room_id, {
                    "type": "chat",
                    "username": username,
                    "message": msg,
                    "timestamp": datetime.utcnow().isoformat()
                })
            elif action == "leave":
                break
            # Optionally, handle timer/timeout/game end if all players answered...
            # Simplified: let frontend or protocol handle detailed game flow
    except WebSocketDisconnect:
        manager.disconnect(room_id, websocket)
        await manager.broadcast(room_id, {
            "type": "user_left",
            "username": username,
        })

@app.on_event("startup")
async def on_startup():
    await database.connect()
    # Fill in built-in categories and demo questions if empty
    cat_count = await database.fetch_val(sqlalchemy.select([sqlalchemy.func.count()]).select_from(categories))
    if not cat_count:
        # Demo categories
        demo_cats = ["Math", "Physics", "Movies", "Cartoons"]
        await database.execute_many(query=categories.insert(),
                                   values=[{"name": n} for n in demo_cats])
    # Demo questions
    q_count = await database.fetch_val(sqlalchemy.select([sqlalchemy.func.count()]).select_from(questions))
    if not q_count:
        # Insert a couple of demo questions
        cat_rows = await database.fetch_all(categories.select())
        demo_qs = [
            {"category_id": cat_rows[0]["id"], "question": "2+2=?", "choices": ["3", "4", "5"], "answer": "4"},
            {"category_id": cat_rows[1]["id"], "question": "H2O is?", "choices": ["Water", "Oxygen", "Sodium"], "answer": "Water"},
            {"category_id": cat_rows[2]["id"], "question": "Best-selling movie?", "choices": ["Titanic", "Avatar", "Inception"], "answer": "Avatar"},
            {"category_id": cat_rows[3]["id"], "question": "SpongeBob works at?", "choices": ["Krusty Krab", "Krusty Burger", "Pizza Hut"], "answer": "Krusty Krab"},
        ]
        await database.execute_many(query=questions.insert(), values=demo_qs)

@app.on_event("shutdown")
async def on_shutdown():
    await database.disconnect()
