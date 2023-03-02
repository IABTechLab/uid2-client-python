"""Internal module for the auto refresh logic.

Do not use this module directly, import from uid2_client instead, e.g.
>>> from uid2_client import EncryptionKeysAutoRefresher
"""


import datetime as dt
from datetime import timezone
import sys
import threading


class EncryptionKeysAutoRefreshResult:
    """Snapshot of result of a background auto-refresh process.

    Attrs:
        keys (EncryptionKeysCollection): encryption keys refreshed from the UID2 service
                                         (None if refresh has not successfully completed once)
        last_error (tuple): last error encountered by the auto refresh process
                            (exc_type, exc_value, exc_traceback); None if last refresh was successful
        last_success_time (datetime): UTC date/time of the last successful refresh;
                                      None if refresh has not completed successfully even once)
        ready (bool): keys have been refreshed at least once (they may no longer be valid though!)
    """
    def __init__(self, keys, error, last_success):
        self.keys = keys
        self.last_error = error
        self.last_success_time = last_success


    @property
    def ready(self):
        """Returns True if keys have been successfully refreshed at least once, False otherwise."""
        return self.keys is not None


    def __repr__(self):
        return '<{}, {}>'.format(self.keys, self.last_error[1])


class EncryptionKeysAutoRefresher(threading.Thread):
    """Thread for automatically refreshing encryption keys in background.

    The class wraps a thread that will periodically invoke the specified UID2 client
    to fetch the latest encryption keys from the service. You can query the thread
    for the current result: last successfully processed keys and details about the
    last error (if any).

    Methods:
        current_result (EncryptionKeysAutoRefreshResult): latest result of the background auto-refresh
        start: start the thread (inherited from Thread)
        cancel: tell the thread to stop
        join: join the thread until it completes (inherited from Thread)
        run: main thread loop (do not call this directly!)

    The safest way to use the class is through the 'with' statement, e.g.
    >>> with EncryptionKeysAutoRefresher(client, refresh_interval, retry_interval) as refresher:
    >>>     result = refresher.current_result
    >>>     if result.ready:
    >>>         do_work(result.keys)
    """

    def __init__(self, client, refresh_interval, retry_interval):
        """Create a new auto refresher thread.

        You will need to call the start() method to actually begin the auto-refresh process.
        Or better yet use the 'with' statement.

        Args:
            client (Uid2Client): client object for interacting with the UID2 services
            refresh_interval (dt.timedelta): interval to refresh keys after a successful attempt
            retry_interval (dt.timedelta): interval to try refreshing the keys again after a failure
        """
        threading.Thread.__init__(self)
        self._client = client
        self._refresh_interval = refresh_interval.total_seconds()
        self._retry_interval = retry_interval.total_seconds()
        self._finished = threading.Event()
        err = RuntimeError('Refresh has not started or completed yet')
        self._result = EncryptionKeysAutoRefreshResult(None, (RuntimeError, err, None), None)


    def current_result(self):
        """Get snapshot of result of auto refreshing.

        If the thread is running, it can be updating the result reference in between
        calls to current_result. For this reason you should get a snapshot and work with
        it rather than keep invoking the method for performing related checks. For example,
        the following is WRONG:
        >>> if not refresher.current_result().ready:
        >>>     print('refresher failed with error:', refresher.current_result.last_error[1])

        The current result may have been updated in between the two calls and last_error
        may have been reset to None breaking the call to print() function. Take a copy of
        snapshot and work with that instead:
        >>> result = refresher.current_result()
        >>> if not result.ready:
        >>>     print('refresher failed with error:', result.last_error[1])
        """
        return self._result


    def run(self):
        """Thread worker function.

        Do not call this directly, kick off the thread by using the start() function instead.
        """
        while not self._finished.is_set():
            interval = self._refresh_interval if self._try_refresh_keys() else self._retry_interval
            self._finished.wait(interval)


    def cancel(self):
        """Tell the thread to stop."""
        self._finished.set()


    def _try_refresh_keys(self):
        """Invoke UID2 client to refresh latest keys from the service."""
        try:
            keys = self._client.refresh_keys()
            self._result = self._make_success_result(keys)
            return True
        except:
            self._result = self._make_error_result(sys.exc_info())
            return False


    def _make_error_result(self, err):
        return EncryptionKeysAutoRefreshResult(self._result.keys, err, self._result.last_success_time)


    def _make_success_result(self, keys):
        return EncryptionKeysAutoRefreshResult(keys, None, dt.datetime.now(tz=timezone.utc))


    def __enter__(self):
        self.start()
        return self


    def __exit__(self, exc_type, exc_value, traceback):
        self.cancel()
        self.join()
