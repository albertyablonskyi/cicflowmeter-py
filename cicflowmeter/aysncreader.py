from threading import Thread, Event

from scapy.utils import PcapReader, tcpdump
from scapy.sessions import DefaultSession


class AsyncReader(object):
    def __init__(self, *args, **kwargs):
        self.args = args
        self.kwargs = kwargs
        self.running = False
        self.thread = None
        self.results = None

    def _setup_thread(self):
        # type: () -> None
        # Prepare sniffing thread
        self.thread = Thread(
            target=self._run,
            args=self.args,
            kwargs=self.kwargs,
            name="AsyncSniffer"
        )
        self.thread.daemon = True

    def _run(self,
             count=0,  # type: int
             store=True,  # type: bool
             offline=None,  # type: Any
             quiet=False,  # type: bool
             prn=None,  # type: Optional[Callable[[Packet], Any]]
             lfilter=None,  # type: Optional[Callable[[Packet], bool]]
             L2socket=None,  # type: Optional[Type[SuperSocket]]
             timeout=None,  # type: Optional[int]
             opened_socket=None,  # type: Optional[SuperSocket]
             stop_filter=None,  # type: Optional[Callable[[Packet], bool]]
             iface=None,  # type: Optional[_GlobInterfaceType]
             started_callback=None,  # type: Optional[Callable[[], Any]]
             session=None,  # type: Optional[_GlobSessionType]
             session_kwargs={},  # type: Dict[str, Any]
             **karg  # type: Any
             ):

        flt = karg.get('filter')

        self.running = True
        # Start main thread
        # instantiate session
        if not isinstance(session, DefaultSession):
            session = session or DefaultSession
            session = session(prn=prn, store=store,
                              **session_kwargs)
        else:
            session.prn = prn
            session.store = store

        fname = offline
        try:
            with PcapReader(fname
                    # fname if flt is None else tcpdump(fname, args=["-w", "-"], flt=flt, getfd=True, quiet=quiet)
            ) as pcap_reader:
                count = 0
                for pkt in pcap_reader:
                    count +=1
                    # print("Count: ", count, end="\r")
                    session.on_packet_received(pkt)
                    # if count >= 50000:
                    #     break
                # print(count)
        except KeyboardInterrupt:
            raise
        self.running = False
        session.toPacketList()

    def stop(self, join=True):
        """Stops AsyncSniffer if not in async mode"""
        if self.running:
            if join:
                self.join()
                return self.results
            return None
        else:
            raise Exception("Not running ! (check .running attr)")

    def start(self):
        """Starts AsyncSniffer in async mode"""
        self._setup_thread()
        if self.thread:
            self.thread.start()

    def join(self, *args, **kwargs):
        if self.thread:
            self.thread.join(*args, **kwargs)