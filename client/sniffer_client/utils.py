import threading


class StoppableThread(threading.Thread):
    """Thread class with a stop() method. The thread itself has to check
    regularly for the stopped condition.
    
    function to be run in the thread should take "stop_event" as a parameter
    """

    def __init__(self, group=None, target=None, name=None,
                 args=(), kwargs=None, *, daemon=None):
        self._stop_event = threading.Event()
        if kwargs is None:
            kwargs = {}
        if "stop_event" in kwargs:
            raise ValueError("stop_event is a reserved keyword")
        kwargs["stop_event"] = self._stop_event
        super().__init__(group=group, target=target, name=name,
                         args=args, kwargs=kwargs, daemon=daemon)
    
    def stop(self):
        self._stop_event.set()

    def is_stopped(self):
        return self._stop_event.is_set()


class MultiStoppableThreads():
    def __init__(self, callback, daemon=False):
        self._callback = callback
        self._daemon = daemon
        self._threads = dict()

    def start(self, id, *args, **kwargs):
        if id in self._threads:
            self.stop(id)
        self._threads[id] = StoppableThread(target=self._callback, daemon=self._daemon, args=args, kwargs=kwargs)
        self._threads[id].start()

    def stop(self, id):
        if id in self._threads and not self._threads[id].is_stopped():
            self._threads[id].stop()
            if not self._daemon:
                self._threads[id].join()
