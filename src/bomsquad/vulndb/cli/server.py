import uvicorn
from fastapi import FastAPI, Depends
from packageurl import PackageURL
from pydantic import BaseModel
from typer import Typer

from bomsquad.vulndb.cli.purl import get_vulns
from bomsquad.vulndb.db.nvddb import NVDDB
from bomsquad.vulndb.db.osvdb import OSVDB

server_app = Typer(name="server")

app = FastAPI()

# Create a global db instance that can be used across multiple requests
nvd = NVDDB()

def get_nvd_db():
    return nvd

osv = OSVDB()

def get_osv_db():
    return osv

@app.get("/")
async def get_root_status():
    return {"status": "ok"}

@app.get("/cve/id/{cve_id}")
async def get_cve(cve_id: str, db=Depends(get_nvd_db)):
    return db.cve_by_id(cve_id)

@app.get("/cpe/id/{cpe_id}")
async def get_cpe(cpe_id: str, db=Depends(get_nvd_db)):
    return db.cpe_by_name_id(cpe_id)

@app.get("/osv/id/{id}")
async def get_by_id(id: str, db=Depends(get_osv_db)):
    return db.find_by_id_or_alias(id)

class FindFromPurl(BaseModel):
    purl: str

@app.post("/osv/purl")
async def find_by_purl(id: FindFromPurl, db=Depends(get_osv_db)):
    purl = PackageURL.from_string(id.purl)
    return db.find_by_purl(purl)

class FindCveFromPurl(BaseModel):
    purl: str

@app.post("/cve/purl")
async def find_cve_by_purl(id: FindCveFromPurl, db=Depends(get_nvd_db)):
    return get_vulns([id.purl])

admin_app = Typer(name="server")

@server_app.command(name="run")
def _run():
    uvicorn.run(app, host="0.0.0.0", port=8080)

if __name__ == '__main__':
    _run()