import threading
from fastapi import FastAPI,Depends,Request,HTTPException
from pydantic import BaseModel
import hmac
import hashlib
import json
import redis
import time
import uvicorn
import uuid


path = "data/secrets.json"

def get_api_key() -> str:
    try:
        with open(path,"r") as file:
            data = json.load(file)
        return data["key"]    
    except Exception as e:
        raise KeyError(f"Error : {e}")

async def safe_get(req:Request):
    api = req.headers.get("X-API-KEY")
    if not api or not hmac.compare_digest(api,get_api_key()):
        raise HTTPException(status_code = 403,detail = "Forbidden")

app = FastAPI()

@app.get("/")
async def main():
    return "Buyer BOT API"



