"""CAKRA - Main Entry Point

Initializes and runs the CAKRA security scanner with command-line interface.
"""

import asyncio
import logging
import click
from rich.console import Console
from rich.logging import RichHandler
from rich.progress import Progress
from datetime import datetime
import uvicorn
from typing import Optional

from cakra.core.config import ConfigLoader
from cakra.core.database import Database
from cakra.agents.scout import ScoutAgent
from cakra.agents.analyst import ContentAnalyst
from cakra.agents.investigator import PaymentInvestigator
from cakra.agents.mapper import NetworkMapper
from cakra.agents.reporter import Reporter

# Setup rich console and logging
console = Console()
logging.basicConfig(
    level="INFO",
    format="%(message)s",
    datefmt="[%X]",
    handlers=[RichHandler(console=console)]
)

# Load configuration
config = ConfigLoader().get_config()

@click.group()
def cli():
    """CAKRA - AI-Powered Cybersecurity Scanner

    Detects and analyzes illegal websites using advanced AI models.
    """
    pass

@cli.command()
@click.option('--host', '-h', default='0.0.0.0', help='Host to bind to')
@click.option('--port', '-p', default=8000, help='Port to bind to')
@click.option('--reload/--no-reload', default=False, help='Enable auto-reload')
@click.option('--workers', '-w', default=1, help='Number of worker processes')
def serve(host: str, port: int, reload: bool, workers: int):
    """Start the CAKRA API server."""
    console.print("[green]Starting CAKRA API server...[/green]")
    uvicorn.run(
        "cakra.api.app:app",
        host=host,
        port=port,
        reload=reload,
        workers=workers,
        log_level="info"
    )

@cli.command()
@click.argument("url")
@click.option("--deep/--quick", default=False, help="Perform deep or quick scan")
def scan(url: str, deep: bool):
    """Scan a single URL for illegal content."""
    async def run_scan():
        try:
            # Initialize database
            db = Database(config.database)
            await db.init_db()
            
            # Initialize agents
            agents = {
                "scout": ScoutAgent(config.models),
                "analyst": ContentAnalyst(config.models),
                "investigator": PaymentInvestigator(config.models),
                "mapper": NetworkMapper(config.models),
                "reporter": Reporter(config.models)
            }
            
            for agent in agents.values():
                await agent.initialize()
            
            with Progress() as progress:
                task = progress.add_task(f"Scanning {url}...", total=5)
                
                # Scout analysis
                scout_result = await agents["scout"].analyze({"url": url})
                if scout_result.get("error"):
                    console.print(f"[red]Error during scout analysis: {scout_result['error']}")
                    return
                progress.update(task, advance=1)
                
                # Content and payment analysis
                analyst_result, payment_result = await asyncio.gather(
                    agents["analyst"].analyze(scout_result),
                    agents["investigator"].analyze(scout_result)
                )
                progress.update(task, advance=2)
                
                # Network mapping
                mapper_result = await agents["mapper"].analyze({
                    **scout_result,
                    **analyst_result
                })
                progress.update(task, advance=1)
                
                # Report generation
                report_result = await agents["reporter"].analyze({
                    "scout": scout_result,
                    "analyst": analyst_result,
                    "payment": payment_result,
                    "mapper": mapper_result
                })
                progress.update(task, advance=1)
                
                # Save results
                scan_result = {
                    "url": url,
                    "scout_analysis": scout_result,
                    "content_analysis": analyst_result,
                    "payment_analysis": payment_result,
                    "network_analysis": mapper_result,
                    "report": report_result,
                    "timestamp": datetime.utcnow().isoformat()
                }
                
                await db.add_scan_result(scan_result)
                
                # Display results
                console.print("\n[green]Scan completed successfully!")
                console.print("\n[bold]Key Findings:[/bold]")
                console.print(f"Illegal Rate: {analyst_result['illegal_rate']}%")
                console.print(f"Confidence: {analyst_result['confidence']}%")
                
                if payment_result["risk_score"] > 5:
                    console.print("\n[red]High-Risk Payment Channels Detected![/red]")
                    for channel in payment_result.get("payment_channels", []):
                        console.print(f"- {channel['type']}: {channel['identifier']}")
                
                if mapper_result.get("clusters"):
                    console.print("\n[yellow]Operator Clusters Found:[/yellow]")
                    for cluster in mapper_result["clusters"]:
                        console.print(f"- {cluster['type']}: {len(cluster['domains'])} domains")
                
                console.print("\n[bold]Report Summary:[/bold]")
                console.print(report_result["report"][:500] + "...")
                
        except Exception as e:
            console.print(f"[red]Error during scan: {str(e)}")
        finally:
            # Cleanup agents
            for agent in agents.values():
                await agent.cleanup()
    
    asyncio.run(run_scan())

@cli.command()
@click.option('--host', '-h', default='0.0.0.0', help='Host to bind to')
@click.option('--port', '-p', default=8000, help='Port to bind to')
@click.option('--reload/--no-reload', default=False, help='Enable auto-reload')
@click.option('--workers', '-w', default=1, help='Number of worker processes')
def serve(host: str, port: int, reload: bool, workers: int):
    """Start the CAKRA API server."""
    console.print("[green]Starting CAKRA API server...[/green]")
    uvicorn.run(
        "cakra.api.app:app",
        host=host,
        port=port,
        reload=reload,
        workers=workers,
        log_level="info"
    )

@cli.command()
def stats():
    """Show system statistics."""
    async def show_stats():
        try:
            db = Database(config.database)
            await db.init_db()
            
            stats = await db.get_statistics()
            
            console.print("[bold]CAKRA System Statistics[/bold]")
            console.print(f"\nTotal Scans: {stats['total_scans']}")
            console.print(f"Sites Found Illegal: {stats['illegal_sites']}")
            console.print(f"Active Payment Channels: {stats['active_payment_channels']}")
            console.print(f"Operator Clusters: {stats['operator_clusters']}")
            console.print(f"\nLast 24 Hours:")
            console.print(f"- New Scans: {stats['recent_scans']}")
            console.print(f"- High Risk Sites: {stats['recent_high_risk']}")
            
        except Exception as e:
            console.print(f"[red]Error fetching statistics: {str(e)}")
    
    asyncio.run(show_stats())

if __name__ == "__main__":
    cli()