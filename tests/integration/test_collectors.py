"""Integration tests for standard health collectors."""

from shsm.collectors import cpu, disk, memory
from shsm.core.context import Context


def test_cpu_collector(test_db, sample_config):
    ctx = Context(sample_config, test_db)
    m = cpu.measure(interval=0.1)
    output = cpu.evaluate(ctx, m)
    metric_names = [metric.name for metric in output.metrics]
    assert "cpu.percent" in metric_names


def test_memory_collector(test_db, sample_config):
    ctx = Context(sample_config, test_db)
    output = memory.collect(ctx)
    metric_names = [metric.name for metric in output.metrics]
    assert "memory.total_bytes" in metric_names
    total = next(m.value for m in output.metrics if m.name == "memory.total_bytes")
    assert total > 0


def test_disk_collector(test_db, sample_config):
    ctx = Context(sample_config, test_db)
    output = disk.collect(ctx)
    assert len(output.metrics) > 0
