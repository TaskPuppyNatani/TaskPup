# TaskPup

TaskPup is a native Linux process manager built with Python, Qt 6, and psutil. Phase 1 targets Linux Mint Debian Edition 7 with Cinnamon on X11.

Phase 1 covers process discovery, inspection, and management with live system summaries. Phase 2 adds a Performance dashboard for CPU, memory, swap, and GPU monitoring. Phase 2B is in development; desktop GPU validation remains outstanding.

## Install and run

Use Python 3.11 or newer and run these commands from the project directory as your regular desktop user.

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e .
.venv/bin/taskpup
```

If Python cannot create a virtual environment on LMDE, install the distribution's `python3-venv` package. Qt's X11 backend also needs the distribution's XCB libraries, including `libxcb-cursor0`.

## Use the process manager

- Click column headers to sort. Use **Columns** to choose which columns to show. **Tree view** groups visible descendants beneath their parents.
- Search by name, PID, user, or command. **My processes** shows processes owned by your user. Auto-refresh runs every 1.5 seconds. Press **F5** to sample immediately or **Ctrl+F** to focus search.
- Right-click a process for properties, clipboard actions, its executable directory, priority, affinity, and signals. **End task** sends SIGTERM. **Force kill** sends SIGKILL. The tree actions show the exact PIDs that will be signaled, with children handled first.
- **Run new task** (**Ctrl+N**) starts an executable with arguments from your home directory. Quote paths or arguments that contain spaces. Pipes, redirects, and expansions are passed as literal arguments.
- The summary shows system CPU, RAM, swap, and the total number of processes visible to TaskPup in its latest valid system-wide snapshot. Search and ownership filters only affect the table. Per-process CPU shows usage in units of one logical CPU. A multithreaded process can exceed 100%.

TaskPup uses the desktop user's permissions and refuses to start as root. Signals use Linux pidfds and require a kernel with `pidfd_open` support (Linux 5.3 or newer). PID 1, kernel threads, and TaskPup itself are protected. Before signaling, TaskPup checks the PID and start time against the sample. Linux reports start times in clock ticks, so reuse within a single tick can evade that comparison. Once opened, the pidfd stays bound to the same process.

Tree previews are built from a sequential scan of the Linux process table. TaskPup rechecks parent identities before previewing their descendants and sends signals only to the listed targets.

Linux nice and CPU affinity settings apply to the process's main thread. The kernel APIs for these settings accept numeric IDs. TaskPup checks identity and liveness around the calls, but process exit and PID reuse can still race a numeric update. Linux may restrict CPU affinity based on the process's cpuset.

The terminal launcher is the verified startup path on Cinnamon/X11. TaskPup supplies its desktop ID to Qt when a matching `taskpup.desktop` is installed. Live registration through an installed desktop entry is unverified.

## Monitor performance

- Open **Performance** and select **CPU**, **Memory**, **Swap**, or a detected GPU. **Per logical CPU** switches between the aggregate CPU chart and a chart for each logical CPU.
- Choose a history window of 30 seconds, 60 seconds, 5 minutes, or 15 minutes, and a sampling interval of 1, 2, or 5 seconds. The defaults are 60 seconds and 1 second. Hover over a chart for historical readings.
- **Pause** holds the performance history. Process-table auto-refresh and manual refresh have independent controls. Process and thread totals on the CPU page reflect the most recent process scan.
- RAM used is total physical memory minus available memory. The cache and buffer figures are informational and can overlap those totals. Swap activity rates use Linux counter deltas over the measured sample interval.
- CPU temperature, frequency, and topology depend on the system exposing reliable data. Unsupported readings and the first sample of a delta-based metric are shown as unavailable. Systems without configured swap have a capacity of zero and no utilization percentage.
- GPUs are discovered through Linux DRM. AMD `amdgpu` sysfs and hwmon provide utilization, driver memory pools, and available labeled sensors; capabilities vary by hardware and driver. Other drivers, including legacy `radeon`, are identified but detailed telemetry is not currently supported. Device names depend on the local PCI ID database. Discovery occurs when monitoring first starts; restart TaskPup to discover newly attached GPUs.
- The GPU memory graph shows the driver's reported VRAM pool, which can be reserved system memory on integrated graphics and is not necessarily physically dedicated memory. GTT is shown separately as a driver allocation and limit; the limit is not system RAM consumption. These figures are not added together. AMD power readings may include CPU power on APUs. Unavailable or inaccessible metrics are shown as unavailable.
- History is kept in memory and bounded to 15 minutes. Dashboard preferences are restored when TaskPup reopens.

## Development checks

```bash
.venv/bin/python -m pip install -e '.[dev]'
.venv/bin/python -m pytest
.venv/bin/pyright
```

The tests default to Qt's offscreen backend. To test the X11 backend under a temporary X server, run `QT_QPA_PLATFORM=xcb xvfb-run -a .venv/bin/python -m pytest`.
