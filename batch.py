"""
Parallel execution engine for batched API operations.
"""
import asyncio
import time
import random
import logging
import datetime
from typing import List, Callable, Dict, Any, Optional
from dataclasses import dataclass
from client import tracker

logger = logging.getLogger("okta_mcp")

PARALLEL_CONFIG = {
    "defaultConcurrency": 5,
    "maxConcurrency": 20,
    "minDelayMs": 50,
    "maxDelayMs": 200,
}

@dataclass
class BatchedTask:
    id: str
    execute: Callable[[], Any]
    url: Optional[str] = None

class ParallelEngine:
    @staticmethod
    def get_adaptive_delay(index: int, total: int) -> float:
        progress = index / total
        min_delay = PARALLEL_CONFIG["minDelayMs"]
        max_delay = PARALLEL_CONFIG["maxDelayMs"]
        extra = (max_delay - min_delay) * (1 - progress)
        return min_delay + (extra * random.random())

    @staticmethod
    async def execute_parallel(
        tasks: List[BatchedTask],
        concurrency: int = 5,
        stop_on_error: bool = False,
        respect_rate_limits: bool = True
    ):
        concurrency = min(max(1, concurrency), PARALLEL_CONFIG["maxConcurrency"])
        semaphore = asyncio.Semaphore(concurrency)
        
        results = {
            "succeeded": [],
            "failed": [],
            "total": len(tasks),
            "concurrency": concurrency,
            "startTime": time.time(),
            "rateLimitWaits": 0,
            "totalRateLimitWaitMs": 0,
        }
        
        completed_count = 0
        should_stop = False
        
        async def worker(task: BatchedTask, index: int):
            nonlocal completed_count, should_stop
            
            if should_stop:
                return {"id": task.id, "skipped": True, "reason": "stopped_early"}

            async with semaphore:
                if respect_rate_limits and task.url:
                    check = tracker.can_make_request(task.url)
                    if not check["canProceed"]:
                        wait_ms = check["waitMs"]
                        logger.warning(f"[PARALLEL] Task {task.id} waiting {wait_ms/1000:.1f}s for rate limit")
                        results["rateLimitWaits"] += 1
                        results["totalRateLimitWaitMs"] += wait_ms
                        await asyncio.sleep(wait_ms / 1000.0)

                delay_ms = ParallelEngine.get_adaptive_delay(index, len(tasks))
                await asyncio.sleep(delay_ms / 1000.0)

                start_ts = time.time()
                try:
                    if should_stop:
                         return {"id": task.id, "skipped": True}

                    res_data = await task.execute()
                    duration_ms = (time.time() - start_ts) * 1000
                    
                    task_res = {
                        "id": task.id,
                        "success": True,
                        "result": res_data,
                        "duration": f"{duration_ms:.2f}ms",
                        "index": index
                    }
                    results["succeeded"].append(task_res)
                    logger.info(f"[PARALLEL] ✅ {completed_count+1}/{len(tasks)} - {task.id}")
                    
                except Exception as e:
                    duration_ms = (time.time() - start_ts) * 1000
                    task_res = {
                        "id": task.id,
                        "success": False,
                        "error": str(e),
                        "duration": f"{duration_ms:.2f}ms",
                        "index": index
                    }
                    if hasattr(e, 'response'):
                        task_res['errorResponse'] = e.response
                    
                    results["failed"].append(task_res)
                    logger.error(f"[PARALLEL] ❌ {completed_count+1}/{len(tasks)} - {task.id}: {str(e)}")
                    
                    if stop_on_error:
                        should_stop = True
                finally:
                    completed_count += 1

        await asyncio.gather(*[worker(t, i) for i, t in enumerate(tasks)])

        total_duration = (time.time() - results["startTime"]) * 1000
        results["totalDuration"] = f"{total_duration:.2f}ms"
        results["averagePerTask"] = f"{total_duration / len(tasks):.2f}ms" if tasks else "0ms"
        
        duration_sec = total_duration / 1000
        throughput = len(tasks) / duration_sec if duration_sec > 0 else 0
        results["throughput"] = f"{throughput:.2f} tasks/sec"
        
        results["startTime"] = datetime.datetime.fromtimestamp(results["startTime"], datetime.timezone.utc).isoformat()
        results["endTime"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        
        return results
