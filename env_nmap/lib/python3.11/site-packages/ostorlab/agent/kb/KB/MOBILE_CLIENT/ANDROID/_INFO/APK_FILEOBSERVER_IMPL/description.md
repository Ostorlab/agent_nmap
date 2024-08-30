Monitors files (using inotify) to fire an event after files are accessed or changed by any process on the device (including this one). FileObserver is an abstract class; subclasses must implement the event handler onEvent(int, java.lang.String).

Each FileObserver instance can monitor multiple files or directories. If a directory is monitored, events will be triggered for all files and subdirectories inside the monitored directory.

An event mask is used to specify which changes or actions to report. Event type constants are used to describe the possible changes in the event mask as well as what actually happened in event callbacks.
