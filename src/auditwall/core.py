import importlib
import os
import sys
import traceback
from contextlib import contextmanager
from types import ModuleType


class SideEffectDetected(Exception):
    """Exception raised when a forbidden side effect is detected by the audit wall."""

    pass


class AuditWallConfig:
    """Configuration for the AuditWall.

    This class allows configuring which operations are allowed or blocked.
    """

    def __init__(self):
        # Default blocked open flags
        self.blocked_open_flags = (
            os.O_WRONLY | os.O_RDWR | os.O_APPEND | os.O_CREAT | os.O_EXCL | os.O_TRUNC
        )

        # Default allowed file paths for writing (e.g., /dev/null)
        self.allowed_write_paths = {"/dev/null", "nul"}

        # Modules that are allowed to use subprocess
        self.allowed_subprocess_modules = {"_aix_support", "ctypes", "platform", "uuid"}

        # Events that are explicitly blocked
        self.blocked_events = {
            "winreg.CreateKey",
            "winreg.DeleteKey",
            "winreg.DeleteValue",
            "winreg.SaveKey",
            "winreg.SetValue",
            "winreg.DisableReflectionKey",
            "winreg.EnableReflectionKey",
        }

        # Events that are explicitly allowed
        self.allowed_events = {
            "os.putenv",
            "os.unsetenv",
            "msvcrt.heapmin",
            "msvcrt.kbhit",
            "glob.glob",
            "msvcrt.get_osfhandle",
            "msvcrt.setmode",
            "os.listdir",
            "os.scandir",
            "os.chdir",
            "os.fwalk",
            "os.getxattr",
            "os.listxattr",
            "os.walk",
            "pathlib.Path.glob",
            "socket.gethostbyname",
            "socket.__new__",
            "socket.bind",
            "socket.connect",
        }

        # Prefixes of events that are blocked by default
        self.blocked_event_prefixes = {
            "os",
            "fcntl",
            "ftplib",
            "glob",
            "imaplib",
            "msvcrt",
            "nntplib",
            "pathlib",
            "poplib",
            "shutil",
            "smtplib",
            "socket",
            "sqlite3",
            "subprocess",
            "telnetlib",
            "urllib",
            "webbrowser",
        }

        # Custom handlers for specific events
        self.special_handlers = {}


class AuditWall:
    """Class that handles audit events and blocks potentially dangerous operations.

    This class provides an audit wall that prevents side effects during code execution.
    It can be configured to allow or block specific operations.
    """

    def __init__(self, config: AuditWallConfig | None = None):
        """Initialize the AuditWall with optional configuration.

        Args:
            config: Configuration for the audit wall. If None, default configuration is used.
        """
        self.config = config or AuditWallConfig()
        self._handlers: dict[str, callable] = {}
        self._enabled = False
        self._modules_with_allowed_popen: set[ModuleType] | None = None

    def accept(self, event: str, args: tuple) -> None:
        """Accept an audit event (do nothing).

        Args:
            event: The audit event name.
            args: The arguments passed with the event.
        """
        pass

    def reject(self, event: str, args: tuple) -> None:
        """Reject an audit event by raising a SideEffectDetected exception.

        Args:
            event: The audit event name.
            args: The arguments passed with the event.
        """
        raise SideEffectDetected(
            f'A "{event}{args}" operation was detected. '
            f"Operation blocked by AuditWall - potentially unsafe side effect"
        )

    def inside_module(self, modules: list[ModuleType] | set[ModuleType]) -> bool:
        """Check if the current stack trace is inside one of the given modules.

        Args:
            modules: The modules to check.

        Returns:
            True if the current stack trace is inside one of the modules, False otherwise.
        """
        files = {m.__file__ for m in modules}
        for frame, lineno in traceback.walk_stack(None):
            if frame.f_code.co_filename in files:
                return True
        return False

    def check_open(self, event: str, args: tuple) -> None:
        """Check if a file open operation is allowed.

        Args:
            event: The audit event name.
            args: The arguments passed with the event.

        Raises:
            SideEffectDetected: If the file open operation is not allowed.
        """
        (filename_or_descriptor, mode, flags) = args
        if filename_or_descriptor in self.config.allowed_write_paths:
            # (no-op writes on unix/windows)
            return
        if flags & self.config.blocked_open_flags:
            raise SideEffectDetected(
                f'We\'ve blocked a file writing operation on "{filename_or_descriptor}". '
                f"AuditWall blocks operations with side effects"
            )

    def check_msvcrt_open(self, event: str, args: tuple) -> None:
        """Check if a msvcrt open operation is allowed.

        Args:
            event: The audit event name.
            args: The arguments passed with the event.

        Raises:
            SideEffectDetected: If the msvcrt open operation is not allowed.
        """
        (handle, flags) = args
        if flags & self.config.blocked_open_flags:
            raise SideEffectDetected(
                f'We\'ve blocked a file writing operation on "{handle}". '
                f"AuditWall blocks operations with side effects"
            )

    def modules_with_allowed_popen(self) -> set[ModuleType]:
        """Get modules that are allowed to use subprocess.

        Returns:
            A set of modules that are allowed to use subprocess.
        """
        if self._modules_with_allowed_popen is None:
            self._modules_with_allowed_popen = set()
            for module_name in self.config.allowed_subprocess_modules:
                try:
                    self._modules_with_allowed_popen.add(
                        importlib.import_module(module_name)
                    )
                except ImportError:
                    pass
        return self._modules_with_allowed_popen

    def check_subprocess(self, event: str, args: tuple) -> None:
        """Check if a subprocess operation is allowed.

        Args:
            event: The audit event name.
            args: The arguments passed with the event.

        Raises:
            SideEffectDetected: If the subprocess operation is not allowed.
        """
        if not self.inside_module(self.modules_with_allowed_popen()):
            self.reject(event, args)

    def make_handler(self, event: str) -> callable:
        """Create a handler for the given audit event.

        Args:
            event: The audit event name.

        Returns:
            A handler function for the event.
        """
        # Check if there's a custom handler registered for this event
        if event in self.config.special_handlers:
            return self.config.special_handlers[event]

        # Check if there's a method handler for this event
        special_handlers = {
            "open": self.check_open,
            "subprocess.Popen": self.check_subprocess,
            "msvcrt.open_osfhandle": self.check_msvcrt_open,
        }

        special_handler = special_handlers.get(event, None)
        if special_handler:
            return special_handler

        # Block events that are explicitly blocked
        if event in self.config.blocked_events:
            return self.reject

        # Allow events that are explicitly allowed
        if event in self.config.allowed_events:
            return self.accept

        # Block groups of events based on prefix
        event_prefix = event.split(".", 1)[0]
        if event_prefix in self.config.blocked_event_prefixes:
            return self.reject

        # Allow other events by default
        return self.accept

    def audithook(self, event: str, args: tuple) -> None:
        """Handle an audit event.

        Args:
            event: The audit event name.
            args: The arguments passed with the event.
        """
        if not self._enabled:
            return

        handler = self._handlers.get(event)
        if handler is None:
            handler = self.make_handler(event)
            self._handlers[event] = handler

        handler(event, args)

    def register_handler(self, event: str, handler: callable) -> None:
        """Register a custom handler for an audit event.

        Args:
            event: The audit event name.
            handler: The handler function.
        """
        self.config.special_handlers[event] = handler
        # Clear cached handler if it exists
        if event in self._handlers:
            del self._handlers[event]

    @contextmanager
    def opened(self):
        """Context manager for temporarily disabling the audit wall.

        Yields:
            None
        """
        assert self._enabled
        self._enabled = False
        try:
            yield
        finally:
            self._enabled = True

    def enable(self) -> None:
        """Enable the audit wall."""
        sys.dont_write_bytecode = True  # disable .pyc file writing
        sys.addaudithook(self.audithook)
        self._enabled = True

    def disable(self) -> None:
        """Disable the audit wall."""
        self._enabled = False


_default_audit_wall = AuditWall()

def engage_auditwall() -> None:
    """Enable the default audit wall."""
    _default_audit_wall.enable()


def disable_auditwall() -> None:
    """Disable the default audit wall."""
    _default_audit_wall.disable()


@contextmanager
def opened_auditwall():
    with _default_audit_wall.opened():
        yield
