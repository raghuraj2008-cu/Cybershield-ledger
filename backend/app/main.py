from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.api.endpoints import router as api_router

app = FastAPI(
    title="CyberShield Ledger API",
    description="Autonomous EDR Ingestion, Merkle Anchoring & SOAR Platform",
    version="1.0.0"
)

# Enable CORS for local UI and Live Server access
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(api_router, prefix="/api/v1")

@app.get("/")
def root():
    return {"status": "CyberShield EDR Backend Operational"}