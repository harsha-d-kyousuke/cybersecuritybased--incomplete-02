# backend/main.py
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel
from typing import List, Optional
import jwt
import bcrypt
from datetime import datetime, timedelta
import asyncpg
import os
from contextlib import asynccontextmanager
import logging

# Import attack modules
from attacks.sql_injection import SQLInjectionAttack
from attacks.xss import XSSAttack
from attacks.csrf import CSRFAttack
from attacks.brute_force import BruteForceAttack
from attacks.directory_traversal import DirectoryTraversalAttack
from reports.report_generator import ReportGenerator
from ai.fix_recommender import FixRecommender

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Configuration
SECRET_KEY = os.getenv("SECRET_KEY", "your-secret-key-here")
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://user:password@localhost/cyberattack_db")
JWT_ALGORITHM = "HS256"
JWT_EXPIRE_HOURS = 24

# Security
security = HTTPBearer()

# Database connection pool
db_pool = None

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    global db_pool
    db_pool = await asyncpg.create_pool(DATABASE_URL)
    logger.info("Database connection pool created")
    yield
    # Shutdown
    await db_pool.close()
    logger.info("Database connection pool closed")

# FastAPI app
app = FastAPI(
    title="Cybersecurity Attack Simulator",
    description="Professional-grade cybersecurity testing platform",
    version="1.0.0",
    lifespan=lifespan
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Pydantic models
class UserCreate(BaseModel):
    username: str
    email: str
    password: str
    role: str = "user"

class UserLogin(BaseModel):
    username: str
    password: str

class AttackRequest(BaseModel):
    attack_type: str
    target_url: str
    parameters: dict = {}

class User(BaseModel):
    id: int
    username: str
    email: str
    role: str
    created_at: datetime

class AttackResult(BaseModel):
    attack_id: int
    attack_type: str
    target_url: str
    vulnerabilities_found: List[dict]
    severity_score: float
    timestamp: datetime
    recommendations: List[str]

# Authentication helpers
def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))

def create_access_token(data: dict) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(hours=JWT_EXPIRE_HOURS)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=JWT_ALGORITHM)

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    try:
        token = credentials.credentials
        payload = jwt.decode(token, SECRET_KEY, algorithms=[JWT_ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid token")
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid token")
    
    async with db_pool.acquire() as conn:
        user_record = await conn.fetchrow(
            "SELECT * FROM users WHERE username = $1", username
        )
        if user_record is None:
            raise HTTPException(status_code=401, detail="User not found")
        
        return User(
            id=user_record['id'],
            username=user_record['username'],
            email=user_record['email'],
            role=user_record['role'],
            created_at=user_record['created_at']
        )

# API Routes

@app.post("/api/auth/register")
async def register(user_data: UserCreate):
    hashed_password = hash_password(user_data.password)
    
    try:
        async with db_pool.acquire() as conn:
            # Check if user exists
            existing_user = await conn.fetchrow(
                "SELECT id FROM users WHERE username = $1 OR email = $2",
                user_data.username, user_data.email
            )
            if existing_user:
                raise HTTPException(status_code=400, detail="User already exists")
            
            # Create user
            user_id = await conn.fetchval(
                """INSERT INTO users (username, email, password_hash, role, created_at)
                   VALUES ($1, $2, $3, $4, $5) RETURNING id""",
                user_data.username, user_data.email, hashed_password,
                user_data.role, datetime.utcnow()
            )
            
            # Create access token
            access_token = create_access_token({"sub": user_data.username})
            
            return {
                "access_token": access_token,
                "token_type": "bearer",
                "user_id": user_id,
                "username": user_data.username
            }
    except Exception as e:
        logger.error(f"Registration error: {str(e)}")
        raise HTTPException(status_code=500, detail="Registration failed")

@app.post("/api/auth/login")
async def login(user_credentials: UserLogin):
    try:
        async with db_pool.acquire() as conn:
            user_record = await conn.fetchrow(
                "SELECT * FROM users WHERE username = $1",
                user_credentials.username
            )
            
            if not user_record or not verify_password(
                user_credentials.password, user_record['password_hash']
            ):
                raise HTTPException(status_code=401, detail="Invalid credentials")
            
            access_token = create_access_token({"sub": user_credentials.username})
            
            return {
                "access_token": access_token,
                "token_type": "bearer",
                "user_id": user_record['id'],
                "username": user_record['username'],
                "role": user_record['role']
            }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Login error: {str(e)}")
        raise HTTPException(status_code=500, detail="Login failed")

@app.get("/api/auth/me", response_model=User)
async def get_current_user_info(current_user: User = Depends(get_current_user)):
    return current_user

@app.post("/api/attacks/execute", response_model=AttackResult)
async def execute_attack(
    attack_request: AttackRequest,
    current_user: User = Depends(get_current_user)
):
    try:
        # Initialize attack modules
        attack_modules = {
            "sql_injection": SQLInjectionAttack(),
            "xss": XSSAttack(),
            "csrf": CSRFAttack(),
            "brute_force": BruteForceAttack(),
            "directory_traversal": DirectoryTraversalAttack()
        }
        
        if attack_request.attack_type not in attack_modules:
            raise HTTPException(status_code=400, detail="Invalid attack type")
        
        # Execute attack
        attack_module = attack_modules[attack_request.attack_type]
        vulnerabilities = await attack_module.execute(
            attack_request.target_url,
            attack_request.parameters
        )
        
        # Calculate severity score
        severity_score = calculate_severity_score(vulnerabilities)
        
        # Get AI recommendations
        fix_recommender = FixRecommender()
        recommendations = await fix_recommender.generate_recommendations(
            attack_request.attack_type, vulnerabilities
        )
        
        # Store attack result in database
        async with db_pool.acquire() as conn:
            attack_id = await conn.fetchval(
                """INSERT INTO attack_results 
                   (user_id, attack_type, target_url, vulnerabilities_found, 
                    severity_score, timestamp, recommendations)
                   VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id""",
                current_user.id,
                attack_request.attack_type,
                attack_request.target_url,
                str(vulnerabilities),  # JSON string
                severity_score,
                datetime.utcnow(),
                str(recommendations)  # JSON string
            )
        
        return AttackResult(
            attack_id=attack_id,
            attack_type=attack_request.attack_type,
            target_url=attack_request.target_url,
            vulnerabilities_found=vulnerabilities,
            severity_score=severity_score,
            timestamp=datetime.utcnow(),
            recommendations=recommendations
        )
        
    except Exception as e:
        logger.error(f"Attack execution error: {str(e)}")
        raise HTTPException(status_code=500, detail="Attack execution failed")

@app.get("/api/attacks/history")
async def get_attack_history(current_user: User = Depends(get_current_user)):
    try:
        async with db_pool.acquire() as conn:
            records = await conn.fetch(
                """SELECT * FROM attack_results 
                   WHERE user_id = $1 ORDER BY timestamp DESC LIMIT 50""",
                current_user.id
            )
            
            return [dict(record) for record in records]
    except Exception as e:
        logger.error(f"History retrieval error: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to retrieve history")

@app.get("/api/dashboard/stats")
async def get_dashboard_stats(current_user: User = Depends(get_current_user)):
    try:
        async with db_pool.acquire() as conn:
            # Total attacks
            total_attacks = await conn.fetchval(
                "SELECT COUNT(*) FROM attack_results WHERE user_id = $1",
                current_user.id
            )
            
            # Vulnerabilities found
            total_vulns = await conn.fetchval(
                """SELECT COUNT(*) FROM attack_results 
                   WHERE user_id = $1 AND vulnerabilities_found != '[]'""",
                current_user.id
            )
            
            # Average severity
            avg_severity = await conn.fetchval(
                "SELECT AVG(severity_score) FROM attack_results WHERE user_id = $1",
                current_user.id
            ) or 0
            
            # Recent attacks by type
            attack_types = await conn.fetch(
                """SELECT attack_type, COUNT(*) as count 
                   FROM attack_results WHERE user_id = $1 
                   GROUP BY attack_type ORDER BY count DESC""",
                current_user.id
            )
            
            return {
                "total_attacks": total_attacks,
                "total_vulnerabilities": total_vulns,
                "average_severity": round(float(avg_severity), 2),
                "attack_types": [dict(record) for record in attack_types]
            }
    except Exception as e:
        logger.error(f"Dashboard stats error: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to retrieve stats")

@app.post("/api/reports/generate/{attack_id}")
async def generate_report(
    attack_id: int,
    current_user: User = Depends(get_current_user)
):
    try:
        async with db_pool.acquire() as conn:
            attack_record = await conn.fetchrow(
                """SELECT * FROM attack_results 
                   WHERE id = $1 AND user_id = $2""",
                attack_id, current_user.id
            )
            
            if not attack_record:
                raise HTTPException(status_code=404, detail="Attack record not found")
        
        # Generate PDF report
        report_generator = ReportGenerator()
        pdf_path = await report_generator.generate_pdf_report(dict(attack_record))
        
        return FileResponse(
            pdf_path,
            media_type="application/pdf",
            filename=f"security_report_{attack_id}.pdf"
        )
        
    except Exception as e:
        logger.error(f"Report generation error: {str(e)}")
        raise HTTPException(status_code=500, detail="Report generation failed")

# Health check
@app.get("/health")
async def health_check():
    return {"status": "healthy", "timestamp": datetime.utcnow()}

# Utility functions
def calculate_severity_score(vulnerabilities: List[dict]) -> float:
    """Calculate CVSS-like severity score"""
    if not vulnerabilities:
        return 0.0
    
    severity_map = {
        "critical": 10.0,
        "high": 8.0,
        "medium": 5.0,
        "low": 2.0,
        "info": 0.5
    }
    
    total_score = sum(
        severity_map.get(vuln.get("severity", "low").lower(), 2.0)
        for vuln in vulnerabilities
    )
    
    return min(total_score / len(vulnerabilities), 10.0)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, reload=True)