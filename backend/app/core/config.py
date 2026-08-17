import os

class Settings:
    PROJECT_NAME: str = "CyberShield Ledger"
    VERSION: str = "1.0.0"
    API_V1_STR: str = "/api/v1"
    SEVERITY_THRESHOLD: int = 90
    BLOCKCHAIN_NETWORK: str = os.getenv("BLOCKCHAIN_NETWORK", "localhost:8545")

settings = Settings()
