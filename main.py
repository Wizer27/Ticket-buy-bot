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
        return data["api"]    
    except Exception as e:
        raise KeyError(f"Error : {e}")

def get_siganture_key() -> str:
    try:
        with open(path,"r") as file:
            data = json.load(file)
        return data["signature"]    
    except Exception as e:
        raise KeyError("No key found")
def get_telebot_token() -> str:
    try:
        with open(path,"r") as file:
            data = json.load(file)
        return data[telebot]    
    except KeyError:
        raise KeyError("No suck key")


def verify_signature(data: dict, received_signature: str) -> bool:
    if time.time() - data.get('timestamp', 0) > 300:
        return False
    KEY = get_siganture_key()
    
    data_to_verify = data.copy()
    data_to_verify.pop("signature", None)
    
    data_str = json.dumps(data_to_verify, sort_keys=True, separators=(',', ':'))
    expected_signature = hmac.new(KEY.encode(), data_str.encode(), hashlib.sha256).hexdigest()
    
    return hmac.compare_digest(received_signature, expected_signature)


async def safe_get(req:Request):
    api = req.headers.get("X-API-KEY")
    if not api or not hmac.compare_digest(api,get_api_key()):
        raise HTTPException(status_code = 403,detail = "Forbidden")

 
app = FastAPI()
bot = telebot.Telebot(get_telebot_token())

@app.get("/")
async def main():
    return "Buyer BOT API"


class Register(BaseModel):
    user_id:str
@app.get("/register")
async def register(req:Register,x_signature:str = Header(...),x_timestamp:str = Header(...)):
    if not verify_signature(req.model_dump(),x_signature,x_timestamp):
        raise HTTPException(status_code = 400,detail = "Invalid signature")
    try:
        pass
    except Exception as e:
        raise HTTPException(status_code = 400,detail = f"Error : {e}")

def run_api():
    uvicorn.run(app,host = "0.0.0.0",port = 8080)
def run_bot():
    bot.polling(none_stop = True)
if __name__ == "__main__":
    threading.Thread(target = run_bot,daemon = True).start()
    run_api()
