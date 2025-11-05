"""Progress tracking for domain checks."""

import time
from typing import Optional

from rich.console import Console
from rich.progress import (
    Progress,
    SpinnerColumn,
    BarColumn,
    TaskProgressColumn,
    TimeRemainingColumn,
    TextColumn,
)


class ProgressTracker:
    """도메인 체크 진행 상황 추적 및 표시"""

    def __init__(self, console: Console, total_domains: int):
        """
        Initialize progress tracker.

        Args:
            console: Rich Console 인스턴스
            total_domains: 전체 도메인 수
        """
        self.console = console
        self.total_domains = total_domains
        self.start_time: Optional[float] = None
        self.task_id: Optional[int] = None
        
        self.progress = Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            TimeRemainingColumn(),
            console=console,
        )

    def start(self) -> None:
        """진행 상황 표시 시작"""
        self.start_time = time.time()
        self.progress.start()
        self.task_id = self.progress.add_task(
            "[cyan]Checking domains...",
            total=self.total_domains
        )

    def update_domain(self, domain: str, status: str = "checking") -> None:
        """
        현재 처리 중인 도메인 업데이트
        
        Args:
            domain: 현재 체크 중인 도메인 이름
            status: 현재 상태 (기본값: "checking")
        """
        if self.task_id is not None:
            self.progress.update(
                self.task_id,
                description=f"[cyan]Checking {domain}..."
            )

    def complete_domain(self, domain: str, status: str) -> None:
        """
        도메인 체크 완료 표시
        
        Args:
            domain: 완료된 도메인 이름
            status: 체크 결과 상태 (OK, WARNING, ERROR, CRITICAL)
        """
        if self.task_id is not None:
            self.progress.advance(self.task_id, 1)

    def finish(self, total_time: Optional[float] = None) -> None:
        """
        진행 상황 표시 종료
        
        Args:
            total_time: 전체 실행 시간 (초). None이면 자동 계산
        """
        if total_time is None and self.start_time is not None:
            total_time = time.time() - self.start_time
        
        self.progress.stop()
        
        if total_time is not None:
            self.console.print(
                f"\n[bold green]✓[/bold green] Completed all checks in "
                f"[bold cyan]{total_time:.2f}[/bold cyan] seconds"
            )
