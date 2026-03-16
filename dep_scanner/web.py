from __future__ import annotations

"""FastAPI web endpoints for path-based and uploaded-file scans."""

from dataclasses import asdict
from pathlib import Path
from tempfile import TemporaryDirectory

from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field

from dep_scanner.scanner import run_scan


class ScanRequest(BaseModel):
    """JSON request schema for manual path scans."""

    inputs: list[str] = Field(default_factory=list)
    ignore_file: str | None = None
    months_unmaintained: int = 18
    github_token: str | None = None


def create_app() -> FastAPI:
    """Create and configure the FastAPI app with scan endpoints."""
    app = FastAPI(title="Dependency Vulnerability Scanner")
    templates = Jinja2Templates(directory=str(Path(__file__).resolve().parent.parent / "templates"))

    @app.get("/", response_class=HTMLResponse)
    async def index(request: Request) -> HTMLResponse:
        """Serve the minimal browser UI."""
        return templates.TemplateResponse(
            request=request,
            name="index.html",
            context={"report": None, "error": None},
        )

    @app.post("/scan")
    async def scan(request_payload: ScanRequest) -> dict:
        """Run a scan against file paths available on the server."""
        if not request_payload.inputs:
            raise HTTPException(status_code=400, detail="Provide at least one input path.")

        report = run_scan(
            input_paths=[Path(value) for value in request_payload.inputs],
            ignore_file=Path(request_payload.ignore_file) if request_payload.ignore_file else None,
            months_unmaintained=request_payload.months_unmaintained,
            github_token=request_payload.github_token,
        )
        return asdict(report)

    @app.post("/scan-upload")
    async def scan_upload(
        files: list[UploadFile] = File(default_factory=list),
        months_unmaintained: int = Form(default=18),
        manual_inputs: str | None = Form(default=None),
        ignore_file: str | None = Form(default=None),
        github_token: str | None = Form(default=None),
    ) -> dict:
        """Run a scan using uploaded files, optionally merged with server paths."""
        manual_paths = []
        if manual_inputs:
            manual_paths = [Path(value.strip()) for value in manual_inputs.splitlines() if value.strip()]
        if not files and not manual_paths:
            raise HTTPException(status_code=400, detail="Provide manual paths or upload at least one file.")

        with TemporaryDirectory() as temp_dir:
            uploaded_paths: list[Path] = []
            temp_path = Path(temp_dir)
            for uploaded_file in files:
                filename = Path(uploaded_file.filename or "").name
                if not filename:
                    continue
                target_path = temp_path / filename
                file_content = await uploaded_file.read()
                target_path.write_bytes(file_content)
                uploaded_paths.append(target_path)

            if not uploaded_paths:
                if not manual_paths:
                    raise HTTPException(status_code=400, detail="Uploaded files are missing filenames.")

            scan_inputs = [*manual_paths, *uploaded_paths]
            report = run_scan(
                input_paths=scan_inputs,
                ignore_file=Path(ignore_file) if ignore_file else None,
                months_unmaintained=months_unmaintained,
                github_token=github_token,
            )
            return asdict(report)

    return app


app = create_app()

