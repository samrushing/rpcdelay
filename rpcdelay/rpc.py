# -*- Python -*-

# based on the eGroups/IronPort fast_rpc implementation.
#
# protocol changes:
#  * 32-bit binary big-endian packet length.
#  * coro.asn1.python codec rather than fpickle.
#  * bidirectional - rpc calls can flow in both directions.
#  * TLS support.
#  * extensible - asn1 encoding allows packets of types other than request/reply.

# See: http://dark.nightmare.com/rushing/misc/protocol/designing_a_protocol.html

"""Implements a simple form of efficient RPC.
   The client has a handle to a remote 'root' object.  It can
   make attribute references on this root, ending in a function
   call.  For example:

   root.sub_object_1.method_3 (arg0, arg1, ...)

   Will send a packet encoding the attribute path (in this case
   ("sub_object_1", "method_3") to the server side, which will call
   method_3() with the given arguments.

   Simple attribute reference is also supported:

   zombie_count = root.zombie_pool.n_zombies

   """

import coro
import errno
import os
import socket
import struct
import sys

# for coro.ssl.Error. I would like a better way to do this.
import coro.ssl

# for encoding names, args & results.
from coro.asn1.python import encode, decode

from coro.log import Facility
LOG = Facility ('rpc')


class ReadyQueue:

    "queue that blocks on pop() but not on push()"

    def __init__ (self):
        self.q = []
        self.cv = coro.condition_variable()

    def __len__ (self):
        return len(self.q)

    def push (self, item):
        if not self.cv.wake_one (item):
            self.q.insert (0, item)

    def pop (self):
        if len(self.q):
            return self.q.pop()
        else:
            return self.cv.wait()

    def pop_all (self):
        if not(len(self.q)):
            return [self.cv.wait()]
        else:
            result, self.q = self.q, []
            return result


class PacketStream:

    """abstract packet streamer.
       uses separate threads for reading and writing packets; supports
       persistent, pipelined protocols.
       implement the <handle_incoming> and <handle_close> methods,
       and call the push() method to send packets.
    """

    def __init__ (self, conn=None):
        self.conn = conn
        self.outgoing = ReadyQueue()
        self.rbytes = 0
        self.wbytes = 0

    def start (self):
        self._send_thread = coro.spawn (self.send_thread)
        self._recv_thread = coro.spawn (self.recv_thread)

    def handle_close (self):
        # make sure they're both killed
        if self._send_thread:
            self._send_thread.shutdown()
        if self._recv_thread:
            self._recv_thread.shutdown()

    def close (self):
        self.handle_close()
        self.conn.close()

    def push (self, packet):
        self.outgoing.push (packet)

    def send_thread (self):
        try:
            peer = self.conn.getpeername()
            LOG ('rpc open', peer)
            while True:
                try:
                    packets = self.outgoing.pop_all()
                    # interleave with packet length headers
                    data = []
                    tlen = 0
                    for p in packets:
                        data.append (struct.pack ('>I', len(p)))
                        data.append (p)
                        tlen += len(p) + 4
                    self.conn.writev (data)
                    self.wbytes += tlen
                except (OSError, coro.ClosedError, coro.ssl.openssl.Error):
                    self._send_thread = None
                    self.handle_close()
                    break
                except coro.Shutdown:
                    # the other thread called handle_close()
                    return
        finally:
            self._send_thread = None
            LOG ('rpc close', peer)

    def recv_thread (self):
        try:
            while True:
                try:
                    size, = struct.unpack ('>I', self.conn.recv_exact (4))
                    packet = self.conn.recv_exact (size)
                    self.rbytes += len(packet) + 4
                    #W ('< %r\n' % (packet,))
                except (EOFError, OSError, coro.ClosedError, struct.error):
                    self._recv_thread = None
                    self.handle_close()
                    break
                except coro.Shutdown:
                    # the other thread called handle_close()
                    return
                else:
                    self.handle_incoming (packet)
        finally:
            self._recv_thread = None


class RPC_Error (Exception):
    pass


class RPC_Connection_Closed (RPC_Error):
    pass


class RPC_Server_Unreachable (RPC_Error):
    pass


class RPC_Remote_Exception (RPC_Error):
    pass


class Proxy:

    "proxy for a remote object"

    def __init__ (self, conn, path=()):
        self.__conn = conn
        self.__path = path

    def __getattr__ (self, attr):
        return Proxy (self.__conn, self.__path + (attr,))

    def __call__ (self, *args):
        return self.__conn.request (self.__path, args)

    def __repr__ (self):
        return '<remote-method-%s at %x>' % ('.'.join (self.__path), id (self))

# initially we define two 'kinds' of packets - requests and replies.
#  an extension to this protocol might define new types for things like
#  asynchronous event delivery.

KIND_REQUEST = 1
KIND_REPLY = 2


class KindError (Exception):
    pass


class Channel (PacketStream):

    def __init__ (self, conn, root=None):
        PacketStream.__init__ (self, conn)
        self.qid_counter = 0
        self.pending_requests = {}
        self.root = root

    debug = False

    def handle_incoming (self, packet):
        # request: packet = (kind, qid, path, params)
        # reply:   packet = (kind, qid, error, result)
        args, plen = decode (packet)
        try:
            args, plen = decode (packet)
        except:
            LOG ('exception decoding packet, closing rpc', packet)
            self.conn.close()
        assert (plen == len(packet))
        if args[0] == KIND_REQUEST:
            self.handle_request (*args[1:])
        elif args[0] == KIND_REPLY:
            self.handle_reply (*args[1:])
        else:
            self.handle_kind (args)

    def handle_kind (self, args):
        raise KindError (args[0])

    def handle_request (self, qid, path, params):
        o = self.root
        e = None
        if self.debug:
            LOG ('<-', self.conn.fd, qid, path, params)
        try:
            for p in path:
                o = getattr (o, p)
            result = o (*params)
        except Exception:
            e = (sys.exc_info()[1].__class__.__name__, coro.traceback_data())
            LOG ('exc', e)
            result = None
        if self.debug:
            LOG ('->', self.conn.fd, qid, e, result)
        self.push (encode ([KIND_REPLY, qid, e, result]))

    def handle_reply  (self, qid, error, result):
        if self.debug:
            LOG ('<=', self.conn.fd, qid, error, result)
        thread = self.pending_requests.get (qid, None)
        if thread is None:
            LOG ('unknown reply', qid)
        else:
            try:
                coro.schedule (thread, (error, result))
            except coro.ScheduleError:
                # something (presumably a timeout?) already woke this guy up
                LOG ('handle_reply', 'ScheduleError', (error, result))

    def handle_close (self):
        PacketStream.handle_close (self)
        # fail any pending requests
        for thread in self.pending_requests.values():
            if not thread.scheduled:
                thread.raise_exception (RPC_Connection_Closed)
        self.pending_requests.clear()
        # make sure it's closed
        self.conn.close()
        self.connected = 0

    def get_proxy (self):
        return Proxy (self)

    def request (self, path, params):
        me = coro.current()
        qid = self.qid_counter
        self.qid_counter += 1
        if self.debug:
            LOG ('=>', self.conn.fd, qid, path, params)
        packet = encode ([KIND_REQUEST, qid, path, params])
        self.push (packet)
        try:
            self.pending_requests[qid] = me
            result = me._yield()
        finally:
            if qid in self.pending_requests:
                del self.pending_requests[qid]
        error, result = result
        if error:
            raise RPC_Remote_Exception (*error)
        else:
            return result


class Server_Channel (Channel):

    def __init__ (self, conn, addr, root=None):
        Channel.__init__ (self, conn, root)
        self.addr = addr
        self.start()


class Server:

    buffer_size = 512 * 1024

    def __init__ (self, root, addr, channel_factory=Server_Channel):
        self.root = root
        self.addr = addr
        self.channel_factory = channel_factory
        self.socket = self.make_socket()
        self.socket.setsockopt (socket.SOL_SOCKET, socket.SO_SNDBUF, self.buffer_size)
        self.socket.setsockopt (socket.SOL_SOCKET, socket.SO_RCVBUF, self.buffer_size)
        coro.spawn (self.serve)

    def make_socket (self):
        if isinstance(self.addr, str):
            return coro.unix_sock()
        else:
            return coro.tcp_sock()

    def serve (self):
        self.socket.set_reuse_addr()
        if isinstance(self.addr, str):
            # Unfortunately there is no easy way to determine if someone is
            # already bound to a unix-domain socket.  We could attempt to
            # connect to it first, and see if we get ECONNREFUSED.  Or, Unix
            # could clean up its act and actually honor the reuseaddr flag.
            try:
                os.unlink (self.addr)
            except OSError:
                pass
        self.socket.bind (self.addr)
        self.socket.listen (1024)
        while True:
            try:
                # Initialize addr in case the accept call raises an exception, so
                # that we don't reference an uninitialized variable in the log
                # message that's emitted in the exception handler
                addr = "<socket.accept-failed>"
                conn, addr = self.socket.accept()
                coro.spawn (self.new_channel, conn, addr)
            except Exception as e:
                LOG.exc()

    def new_channel (self, conn, addr):
        return self.channel_factory (conn, addr, self.root)


class Client (Channel):

    """multiplexing rpc client.
    client yields when making an RPC request; is resumed when
    the reply is returned.  Correctly manages out-of-order replies."""

    # override these to control retry/timeout schedule
    _num_retries = 20
    _retry_timeout = 5

    UNCONNECTED = 0
    CONNECTING = 1
    CONNECTED = 2
    CLOSED = 3

    def __init__ (self, addr, root=None):
        Channel.__init__ (self, None, root)
        self.addr = addr
        self.root = root
        self.state = self.UNCONNECTED
        self.connection_cv = coro.condition_variable()
        self.get_connected()

    def make_socket (self):
        if isinstance(self.addr, str):
            return coro.unix_sock()
        else:
            return coro.tcp_sock()

    def close (self):
        self.state = self.CLOSED
        Channel.close (self)

    buffer_size = 512 * 1024

    def _connect (self):
        self.conn = self.make_socket()
        self.conn.setsockopt (socket.SOL_SOCKET, socket.SO_SNDBUF, self.buffer_size)
        self.conn.setsockopt (socket.SOL_SOCKET, socket.SO_RCVBUF, self.buffer_size)
        self.conn.connect (self.addr)
        self.state = self.CONNECTED
        self.start()
        self.connection_cv.wake_all()

    def get_connected (self):
        if self.state == self.UNCONNECTED:
            self.state = self.CONNECTING
            for i in range (self._num_retries):
                try:
                    coro.with_timeout (self._retry_timeout, self._connect)
                except coro.TimeoutError:
                    coro.sleep_relative (self._retry_timeout)
                except OSError as e:
                    # wait a bit, maybe it'll come back up...
                    coro.sleep_relative (self._retry_timeout)
                except:
                    self.state = self.UNCONNECTED
                    raise
                else:
                    return
            # ok, we give up!
            # fail any pending requests
            self.state = self.UNCONNECTED
            for thread in self.pending_requests.values():
                # avoid a race: if the thread is already scheduled, then
                # it's about to be awakened with the result it was looking
                # for, so don't bother trying to interrupt it - this will
                # cause the latent interrupt to show up at a later and
                # bizarre point in the code.  [see bug 5322 and others]
                if not thread.scheduled:
                    thread.raise_exception (RPC_Server_Unreachable)
            # fail anyone waiting on connect
            self.connection_cv.raise_all (RPC_Server_Unreachable)

    def request (self, path, params):

        if self.state == self.CLOSED:
            # closed
            raise RPC_Connection_Closed
        elif self.state != self.CONNECTED:
            if self.state == self.UNCONNECTED:
                coro.spawn (self.get_connected)
            self.connection_cv.wait()

        return Channel.request (self, path, params)

# Consider these classes to be a demo/example: you probably want to configure
#   your CTX in a way specific to your own needs.


class TLS_Server (Server):

    # by default, do not verify client certificates
    verify_tls = False

    def make_socket (self):
        from coro.ssl import openssl, sock, new_ctx
        ctx = new_ctx (proto='tlsv1')
        ctx.use_cert (openssl.x509 (open ('server.crt').read()))
        ctx.use_key (openssl.pkey (open ('server.key').read(), '', True))
        return sock (ctx, verify=self.verify_tls)


class TLS_Client (Client):

    verify_tls = True

    def make_socket (self):
        from coro.ssl import openssl, sock, new_ctx
        ctx = new_ctx (proto='tlsv1')
        return sock (ctx, verify=self.verify_tls)


def enable_debug():
    Channel.debug = True


def disable_debug():
    Channel.debug = False
