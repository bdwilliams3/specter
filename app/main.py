import asyncio
import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
import os

from app.config import settings
from app.database import init_db
# Import models so Base.metadata is populated
import app.models  # noqa: F401

from app.routers import auth, assets, threats, vulnerabilities, graph, scans, reports, metrics, integrations, ws, collector, rules
from app.services.threat_retention import retention_loop
from app.services.inventory_loop import inventory_loop

logging.basicConfig(level=settings.log_level)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Specter starting up — initialising database...")
    await init_db()
    logger.info("Database ready.")
    purge_task = asyncio.create_task(retention_loop())
    inventory_task = asyncio.create_task(inventory_loop())
    yield
    purge_task.cancel()
    inventory_task.cancel()
    logger.info("Specter shutting down.")


app = FastAPI(
    title="Specter",
    description="AI Security Monitoring Platform",
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/api/docs",
    redoc_url="/api/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# API routers
app.include_router(auth.router)
app.include_router(assets.router)
app.include_router(threats.router)
app.include_router(vulnerabilities.router)
app.include_router(graph.router)
app.include_router(scans.router)
app.include_router(reports.router)
app.include_router(metrics.router)
app.include_router(integrations.router)
app.include_router(ws.router)
app.include_router(collector.router)
app.include_router(rules.router)


@app.get("/healthz")
async def health():
    return {"status": "ok", "app": settings.app_name}


# Serve React frontend from /static (built by multi-stage Docker)
static_dir = "/app/static"
if os.path.isdir(static_dir):
    app.mount("/", StaticFiles(directory=static_dir, html=True), name="frontend")
