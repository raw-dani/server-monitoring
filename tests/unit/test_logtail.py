"""Unit tests for incremental log file tailing."""

import os
from datetime import datetime, timezone

from shsm.utils.logtail import LogTailer


def test_incremental_log_tailing(temp_dir, test_db):
    tailer = LogTailer(test_db)
    log_file = os.path.join(temp_dir, "test.log")
    now = datetime.now(timezone.utc)

    # Step 1: Write 3 lines
    with open(log_file, "w", encoding="utf-8") as f:
        f.write("Line 1\nLine 2\nLine 3\n")

    res = tailer.read_new(log_file, now, start_at_end_on_first_seen=False)
    assert len(res.lines) == 3
    assert res.lines[0] == "Line 1"
    assert res.lines[2] == "Line 3"

    # Step 2: Read again without new writes - should return 0 new lines
    res2 = tailer.read_new(log_file, now)
    assert len(res2.lines) == 0

    # Step 3: Append 2 more lines
    with open(log_file, "a", encoding="utf-8") as f:
        f.write("Line 4\nLine 5\n")

    res3 = tailer.read_new(log_file, now)
    assert len(res3.lines) == 2
    assert res3.lines[0] == "Line 4"
    assert res3.lines[1] == "Line 5"
