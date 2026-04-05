from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, HttpUrl
import httpx

from checks.headers import check_headers

app = FastAPI(title="Web Vulnerability Scanner")

# Allow the React frontend (running on port 5173) to talk to this backend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# Defines the shape of the JSON body the frontend sends
class ScanRequest(BaseModel):
    url: HttpUrl


@app.get("/")
def root():
    return {"message": "Web Vulnerability Scanner API is running"}


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/scan")
async def scan(request: ScanRequest):
    url = str(request.url)

    try:
        header_results = await check_headers(url)
    except httpx.RequestError as e:
        raise HTTPException(status_code=400, detail=f"Could not reach {url}: {e}")

    return {
        "url": url,
        "checks": {
            "headers": header_results,
        },
    }
