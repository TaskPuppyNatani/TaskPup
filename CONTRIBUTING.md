# Contributing

Thanks for taking an interest in TaskPup. Keep changes focused, preserve the regular-user and process-safety boundaries, and include regression tests when behavior changes.

## Development setup

TaskPup requires Python 3.11 or newer. From the repository root:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e '.[dev]'
```

## Checks

```bash
.venv/bin/python -m pytest
.venv/bin/pyright
git diff --check
```

Tests use Qt's offscreen backend by default. To exercise the X11 backend under a temporary X server:

```bash
QT_QPA_PLATFORM=xcb xvfb-run -a .venv/bin/python -m pytest
```

## AppImage packaging

The AppImage workflow is experimental; an official AppImage release has not been published. Read the [packaging guide](packaging/appimage/README.md) before building. Release-mode builds require a clean checkout. Experimental builds capture and hash the source snapshot, including uncommitted and untracked inputs.

## Project structure

- `src/taskpup/` contains the Qt application, Linux process and system integrations, and report code.
- `tests/` contains automated tests.
- `docs/USER_GUIDE.md` describes user-facing features, metric definitions, tested environments, and limitations.
- `packaging/appimage/` contains the AppImage build workflow and its technical documentation.
