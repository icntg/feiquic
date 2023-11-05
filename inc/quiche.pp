unit quiche;



interface
{
  Automatically converted by H2Pas 1.0.0 from quiche.h
  The following command line parameters were used:
    quiche.h
}
    //{$INCLUDE ctypes.inc}
    uses Windows, Sockets, ctypes, winsock2, types;

    Type
    //bool = longbool;
    //cuint64 = QWord;
    //size_t = cuint64;
    //Puint8 = ^uint8;
    //cuint32 = LongWord;
    socklen_t = tsocklen;
    uint8_t = uint8;
    uint16_t = uint16;
    uint32_t = uint32;
    uint64_t = uint64;
    int64_t = int64;
    time_t = cint64;
    
    timespec = record
      tv_sec: time_t; //Seconds
      tv_nsec: clong; //Nanoseconds
    end;

    quiche_config = record
    end;
    quiche_conn = record
    end;
    quiche_h3_config = record
    end;
    quiche_h3_conn = record
    end;
    quiche_h3_event = record
    end;
    quiche_h3_header = record
        name: Puint8;
        name_len: size_t;
        value: Puint8;
        value_len: size_t;
    end;

    quiche_h3_priority = record
                       urgency: uint8;
                       incremental: bool;
    end;

    quiche_path_stats = record
      local_addr : sockaddr_storage;
      local_addr_len : socklen_t;
      peer_addr : sockaddr_storage;
      peer_addr_len : socklen_t;
      validation_state : ssize_t;
      active : bool;
      recv : size_t;
      sent : size_t;
      lost : size_t;
      retrans : size_t;
      rtt : uint64_t;
      cwnd : size_t;
      sent_bytes : uint64_t;
      recv_bytes : uint64_t;
      lost_bytes : uint64_t;
      stream_retrans_bytes : uint64_t;
      pmtu : size_t;
      delivery_rate : uint64_t;
    end;

    quiche_send_info = record
      from_sock : sockaddr_storage;
      from_len : socklen_t;
      to_sock : sockaddr_storage;
      to_len : socklen_t;
      at : timespec;
    end;

    quiche_recv_info = record
      from_sock: ^sockaddr;
      from_len: socklen_t;
      to_sock: ^sockaddr;
      to_len: socklen_t;
    end;


    quiche_stats = record
        recv : size_t;
        sent : size_t;
        lost : size_t;
        retrans : size_t;
        sent_bytes : uint64_t;
        recv_bytes : uint64_t;
        lost_bytes : uint64_t;
        stream_retrans_bytes : uint64_t;
        paths_count : size_t;
    end;

    quiche_stream_iter = record
                       // todo
    end;

    quiche_transport_params = record
        peer_max_idle_timeout : uint64_t;
        peer_max_udp_payload_size : uint64_t;
        peer_initial_max_data : uint64_t;
        peer_initial_max_stream_data_bidi_local : uint64_t;
        peer_initial_max_stream_data_bidi_remote : uint64_t;
        peer_initial_max_stream_data_uni : uint64_t;
        peer_initial_max_streams_bidi : uint64_t;
        peer_initial_max_streams_uni : uint64_t;
        peer_ack_delay_exponent : uint64_t;
        peer_max_ack_delay : uint64_t;
        peer_disable_active_migration : bool;
        peer_active_conn_id_limit : uint64_t;
        peer_max_datagram_frame_size : ssize_t;
    end;

    Pbool  = ^bool;
    Pchar  = ^char;
    Pquiche_config  = ^quiche_config;
    Pquiche_conn  = ^quiche_conn;
    Pquiche_h3_config  = ^quiche_h3_config;
    Pquiche_h3_conn  = ^quiche_h3_conn;
    Pquiche_h3_event  = ^quiche_h3_event;
    PPquiche_h3_event = ^Pquiche_h3_event;
    Pquiche_h3_header  = ^quiche_h3_header;
    Pquiche_h3_priority  = ^quiche_h3_priority;
    Pquiche_path_stats  = ^quiche_path_stats;
    Pquiche_recv_info  = ^quiche_recv_info;
    Pquiche_send_info  = ^quiche_send_info;
    Pquiche_stats  = ^quiche_stats;
    Pquiche_stream_iter  = ^quiche_stream_iter;
    Pquiche_transport_params  = ^quiche_transport_params;
    Psize_t  = ^size_t;
    Psockaddr  = ^sockaddr;
    Puint32_t  = ^uint32_t;
    Puint64_t  = ^uint64_t;
    Puint8_t  = ^uint8_t;
    PPuint8_t = ^Puint8_t;

    TProcedureLogging = procedure (line:Pchar; argp:pointer);
    TFunctionMatching = function (_para1:Puint8_t; _para2:size_t):bool;
    TFunctionCallbackCheck = function (name:Puint8_t; name_len:size_t; value:Puint8_t; value_len:size_t; argp:pointer):longint;
    TFunctionCallbackSettingCheck = function (identifier:uint64_t; value:uint64_t; argp:pointer):longint;
{$IFDEF FPC}
{$PACKRECORDS C}
{$ENDIF}


  { Copyright (C) 2018-2019, Cloudflare, Inc. }
  { All rights reserved. }
  { }
  { Redistribution and use in source and binary forms, with or without }
  { modification, are permitted provided that the following conditions are }
  { met: }
  { }
  {     * Redistributions of source code must retain the above copyright }
  {       notice, this list of conditions and the following disclaimer. }
  { }
  {     * Redistributions in binary form must reproduce the above copyright }
  {       notice, this list of conditions and the following disclaimer in the }
  {       documentation and/or other materials provided with the distribution. }
  { }
  { THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS }
  { IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, }
  { THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR }
  { PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR }
  { CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, }
  { EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, }
  { PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR }
  { PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF }
  { LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING }
  { NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS }
  { SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE. }
{$ifndef QUICHE_H}
{$define QUICHE_H}  
{$if defined(__cplusplus)}
//(* error 
//extern "C" {
{$endif}
//{$include <stdint.h>}
//{$include <stdbool.h>}
//{$include <stddef.h>}
//{$if defined(WIN32) || defined(_WIN32) || defined(__WIN32__) || defined(__NT__)}
//{$include <winsock2.h>}
//{$include <ws2tcpip.h>}
//{$include <time.h>}
//{$else}
//{$include <sys/socket.h>}
//{$include <sys/time.h>}
//{$endif}
//{$ifdef __unix__}
//{$include <sys/types.h>}
//{$endif}
//{$ifdef _MSC_VER}
//{$include <BaseTsd.h>}
//in define line 52 *)
//{$endif}
    { QUIC transport API. }
    { }
    { The current QUIC wire version. }
    const
      QUICHE_PROTOCOL_VERSION = $00000001;      
    { The maximum length of a connection ID. }
      QUICHE_MAX_CONN_ID_LEN = 20;      
    { The minimum length of Initial packets sent by a client. }
      QUICHE_MIN_CLIENT_INITIAL_LEN = 1200;      
    { There is no more work to do. }
    { The provided buffer is too short. }
    { The provided packet cannot be parsed because its version is unknown. }
    { The provided packet cannot be parsed because it contains an invalid }
    { frame. }
    { The provided packet cannot be parsed. }
    { The operation cannot be completed because the connection is in an }
    { invalid state. }
    { The operation cannot be completed because the stream is in an }
    { invalid state. }
    { The peer's transport params cannot be parsed. }
    { A cryptographic operation failed. }
    { The TLS handshake failed. }
    { The peer violated the local flow control limits. }
    { The peer violated the local stream limits. }
    { The specified stream was stopped by the peer. }
    { The specified stream was reset by the peer. }
    { The received data exceeds the stream's final size. }
    { Error in congestion control. }
    { Too many identifiers were provided. }
    { Not enough available identifiers. }
    { Error in key update. }

    type
      quiche_error = (QUICHE_ERR_DONE := -(1),QUICHE_ERR_BUFFER_TOO_SHORT := -(2),
        QUICHE_ERR_UNKNOWN_VERSION := -(3),QUICHE_ERR_INVALID_FRAME := -(4),
        QUICHE_ERR_INVALID_PACKET := -(5),QUICHE_ERR_INVALID_STATE := -(6),
        QUICHE_ERR_INVALID_STREAM_STATE := -(7),
        QUICHE_ERR_INVALID_TRANSPORT_PARAM := -(8),
        QUICHE_ERR_CRYPTO_FAIL := -(9),QUICHE_ERR_TLS_FAIL := -(10),
        QUICHE_ERR_FLOW_CONTROL := -(11),QUICHE_ERR_STREAM_LIMIT := -(12),
        QUICHE_ERR_STREAM_STOPPED := -(15),QUICHE_ERR_STREAM_RESET := -(16),
        QUICHE_ERR_FINAL_SIZE := -(13),QUICHE_ERR_CONGESTION_CONTROL := -(14),
        QUICHE_ERR_ID_LIMIT := -(17),QUICHE_ERR_OUT_OF_IDENTIFIERS := -(18),
        QUICHE_ERR_KEY_UPDATE := -(19));

    { Returns a human readable string with the quiche version number. }
(* Const before type ignored *)

    function quiche_version(): Pchar; stdcall;

    { Enables logging. |cb| will be called with log messages }
(* Const before type ignored *)
    function quiche_enable_debug_logging(cb: TProcedureLogging; argp: pointer):longint;stdcall;

    { Stores configuration shared between multiple connections. }

    // type
    { Creates a config object with the given version. }

    function quiche_config_new(version:uint32_t):Pquiche_config; stdcall;

    { Configures the given certificate chain. }
(* Const before type ignored *)
    function quiche_config_load_cert_chain_from_pem_file(config:Pquiche_config; path:Pchar):longint;

    { Configures the given private key. }
(* Const before type ignored *)
    function quiche_config_load_priv_key_from_pem_file(config:Pquiche_config; path:Pchar):longint;

    { Specifies a file where trusted CA certificates are stored for the purposes of certificate verification. }
(* Const before type ignored *)
    function quiche_config_load_verify_locations_from_file(config:Pquiche_config; path:Pchar):longint;

    { Specifies a directory where trusted CA certificates are stored for the purposes of certificate verification. }
(* Const before type ignored *)
    function quiche_config_load_verify_locations_from_directory(config:Pquiche_config; path:Pchar):longint;

    { Configures whether to verify the peer's certificate. }
    procedure quiche_config_verify_peer(config:Pquiche_config; v:bool);

    { Configures whether to send GREASE. }
    procedure quiche_config_grease(config:Pquiche_config; v:bool);

    { Enables logging of secrets. }
    procedure quiche_config_log_keys(config:Pquiche_config);

    { Enables sending or receiving early data. }
    procedure quiche_config_enable_early_data(config:Pquiche_config);

    { Configures the list of supported application protocols. }
(* Const before type ignored *)
    function quiche_config_set_application_protos(config:Pquiche_config; protos:Puint8_t; protos_len:size_t):longint;

    { Sets the `max_idle_timeout` transport parameter, in milliseconds, default is }
    { no timeout. }
    procedure quiche_config_set_max_idle_timeout(config:Pquiche_config; v:uint64_t);

    { Sets the `max_udp_payload_size transport` parameter. }
    procedure quiche_config_set_max_recv_udp_payload_size(config:Pquiche_config; v:size_t);

    { Sets the maximum outgoing UDP payload size. }
    procedure quiche_config_set_max_send_udp_payload_size(config:Pquiche_config; v:size_t);

    { Sets the `initial_max_data` transport parameter. }
    procedure quiche_config_set_initial_max_data(config:Pquiche_config; v:uint64_t);

    { Sets the `initial_max_stream_data_bidi_local` transport parameter. }
    procedure quiche_config_set_initial_max_stream_data_bidi_local(config:Pquiche_config; v:uint64_t);

    { Sets the `initial_max_stream_data_bidi_remote` transport parameter. }
    procedure quiche_config_set_initial_max_stream_data_bidi_remote(config:Pquiche_config; v:uint64_t);

    { Sets the `initial_max_stream_data_uni` transport parameter. }
    procedure quiche_config_set_initial_max_stream_data_uni(config:Pquiche_config; v:uint64_t);

    { Sets the `initial_max_streams_bidi` transport parameter. }
    procedure quiche_config_set_initial_max_streams_bidi(config:Pquiche_config; v:uint64_t);

    { Sets the `initial_max_streams_uni` transport parameter. }
    procedure quiche_config_set_initial_max_streams_uni(config:Pquiche_config; v:uint64_t);

    { Sets the `ack_delay_exponent` transport parameter. }
    procedure quiche_config_set_ack_delay_exponent(config:Pquiche_config; v:uint64_t);

    { Sets the `max_ack_delay` transport parameter. }
    procedure quiche_config_set_max_ack_delay(config:Pquiche_config; v:uint64_t);

    { Sets the `disable_active_migration` transport parameter. }
    procedure quiche_config_set_disable_active_migration(config:Pquiche_config; v:bool);

    { Sets the congestion control algorithm used by string. }
(* Const before type ignored *)
    function quiche_config_set_cc_algorithm_name(config:Pquiche_config; algo:Pchar):longint;

    { Sets the initial cwnd for the connection in terms of packet count. }
    procedure quiche_config_set_initial_congestion_window_packets(config:Pquiche_config; packets:size_t);


    type
      quiche_cc_algorithm = (QUICHE_CC_RENO := 0,QUICHE_CC_CUBIC := 1,
        QUICHE_CC_BBR := 2,QUICHE_CC_BBR2 := 3
        );

    { Sets the congestion control algorithm used. }

    procedure quiche_config_set_cc_algorithm(config:Pquiche_config; algo:quiche_cc_algorithm);

    { Configures whether to use HyStart++. }
    procedure quiche_config_enable_hystart(config:Pquiche_config; v:bool);

    { Configures whether to enable pacing (enabled by default). }
    procedure quiche_config_enable_pacing(config:Pquiche_config; v:bool);

    { Configures max pacing rate to be used. }
    procedure quiche_config_set_max_pacing_rate(config:Pquiche_config; v:uint64_t);

    { Configures whether to enable receiving DATAGRAM frames. }
    procedure quiche_config_enable_dgram(config:Pquiche_config; enabled:bool; recv_queue_len:size_t; send_queue_len:size_t);

    { Sets the maximum connection window. }
    procedure quiche_config_set_max_connection_window(config:Pquiche_config; v:uint64_t);

    { Sets the maximum stream window. }
    procedure quiche_config_set_max_stream_window(config:Pquiche_config; v:uint64_t);

    { Sets the limit of active connection IDs. }
    procedure quiche_config_set_active_connection_id_limit(config:Pquiche_config; v:uint64_t);

    { Sets the initial stateless reset token. |v| must contain 16 bytes, otherwise the behaviour is undefined. }
(* Const before type ignored *)
    procedure quiche_config_set_stateless_reset_token(config:Pquiche_config; v:Puint8_t);

    { Frees the config object. }
    procedure quiche_config_free(config:Pquiche_config);

    { Extracts version, type, source / destination connection ID and address }
    { verification token from the packet in |buf|. }
(* Const before type ignored *)
    function quiche_header_info(buf:Puint8_t; buf_len:size_t; dcil:size_t; version:Puint32_t; _type:Puint8_t; 
               scid:Puint8_t; scid_len:Psize_t; dcid:Puint8_t; dcid_len:Psize_t; token:Puint8_t; 
               token_len:Psize_t):longint;

    { A QUIC connection. }

    //type
    { Creates a new server-side connection. }
(* Const before type ignored *)
(* Const before type ignored *)
(* Const before type ignored *)
(* Const before type ignored *)

    function quiche_accept(scid:Puint8_t; scid_len:size_t; odcid:Puint8_t; odcid_len:size_t; local:Psockaddr; 
               local_len:size_t; peer:Psockaddr; peer_len:size_t; config:Pquiche_config):Pquiche_conn; stdcall;

    { Creates a new client-side connection. }
(* Const before type ignored *)
(* Const before type ignored *)
(* Const before type ignored *)
(* Const before type ignored *)
    function quiche_connect(server_name:Pchar; scid:Puint8_t; scid_len:size_t; local:Psockaddr; local_len:size_t; 
               peer:Psockaddr; peer_len:size_t; config:Pquiche_config):Pquiche_conn; stdcall;

    { Writes a version negotiation packet. }
(* Const before type ignored *)
(* Const before type ignored *)
    function quiche_negotiate_version(scid:Puint8_t; scid_len:size_t; dcid:Puint8_t; dcid_len:size_t; out_buffer:Puint8_t; 
               out_len:size_t):ssize_t; stdcall;

    { Writes a retry packet. }
(* Const before type ignored *)
(* Const before type ignored *)
(* Const before type ignored *)
(* Const before type ignored *)
    function quiche_retry(scid:Puint8_t; scid_len:size_t; dcid:Puint8_t; dcid_len:size_t; new_scid:Puint8_t; 
               new_scid_len:size_t; token:Puint8_t; token_len:size_t; version:uint32_t; out_buffer:Puint8_t; 
               out_len:size_t):ssize_t;

    { Returns true if the given protocol version is supported. }
    function quiche_version_is_supported(version:uint32_t):bool;

(* Const before type ignored *)
(* Const before type ignored *)
(* Const before type ignored *)
(* Const before type ignored *)
(* Const before type ignored *)
    function quiche_conn_new_with_tls(scid:Puint8_t; scid_len:size_t; odcid:Puint8_t; odcid_len:size_t; local:Psockaddr; 
               local_len:size_t; peer:Psockaddr; peer_len:size_t; config:Pquiche_config; ssl:pointer; 
               is_server:bool):Pquiche_conn;

    { Enables keylog to the specified file path. Returns true on success. }
(* Const before type ignored *)
    function quiche_conn_set_keylog_path(conn:Pquiche_conn; path:Pchar):bool;

    { Enables keylog to the specified file descriptor. Unix only. }
    procedure quiche_conn_set_keylog_fd(conn:Pquiche_conn; fd:longint);

    { Enables qlog to the specified file path. Returns true on success. }
(* Const before type ignored *)
(* Const before type ignored *)
(* Const before type ignored *)
    function quiche_conn_set_qlog_path(conn:Pquiche_conn; path:Pchar; log_title:Pchar; log_desc:Pchar):bool;

    { Enables qlog to the specified file descriptor. Unix only. }
(* Const before type ignored *)
(* Const before type ignored *)
    procedure quiche_conn_set_qlog_fd(conn:Pquiche_conn; fd:longint; log_title:Pchar; log_desc:Pchar);

    { Configures the given session for resumption. }
(* Const before type ignored *)
    function quiche_conn_set_session(conn:Pquiche_conn; buf:Puint8_t; buf_len:size_t):longint;

    { The remote address the packet was received from. }
    { The local address the packet was received on. }


    { Processes QUIC packets received from the peer. }
(* Const before type ignored *)

    function quiche_conn_recv(conn:Pquiche_conn; buf:Puint8_t; buf_len:size_t; info:Pquiche_recv_info):ssize_t;

    { The local address the packet should be sent from. }
    { The remote address the packet should be sent to. }
    { The time to send the packet out. }

    { Writes a single QUIC packet to be sent to the peer. }

    function quiche_conn_send(conn:Pquiche_conn; out_buffer:Puint8_t; out_len:size_t; out_info:Pquiche_send_info):ssize_t;

    { Returns the size of the send quantum, in bytes. }
(* Const before type ignored *)
    function quiche_conn_send_quantum(conn:Pquiche_conn):size_t;

    { Reads contiguous data from a stream. }
    function quiche_conn_stream_recv(conn:Pquiche_conn; stream_id:uint64_t; out_buffer:Puint8_t; buf_len:size_t; fin:Pbool):ssize_t;

    { Writes data to a stream. }
(* Const before type ignored *)
    function quiche_conn_stream_send(conn:Pquiche_conn; stream_id:uint64_t; buf:Puint8_t; buf_len:size_t; fin:bool):ssize_t;

    { The side of the stream to be shut down. }

    type
      quiche_shutdown = (QUICHE_SHUTDOWN_READ := 0,QUICHE_SHUTDOWN_WRITE := 1
        );

    { Sets the priority for a stream. }

    function quiche_conn_stream_priority(conn:Pquiche_conn; stream_id:uint64_t; urgency:uint8_t; incremental:bool):longint;

    { Shuts down reading or writing from/to the specified stream. }
    function quiche_conn_stream_shutdown(conn:Pquiche_conn; stream_id:uint64_t; direction:quiche_shutdown; err:uint64_t):longint;

    { Returns the stream's send capacity in bytes. }
(* Const before type ignored *)
    function quiche_conn_stream_capacity(conn:Pquiche_conn; stream_id:uint64_t):ssize_t;

    { Returns true if the stream has data that can be read. }
(* Const before type ignored *)
    function quiche_conn_stream_readable(conn:Pquiche_conn; stream_id:uint64_t):bool;

    { Returns the next stream that has data to read, or -1 if no such stream is }
    { available. }
    function quiche_conn_stream_readable_next(conn:Pquiche_conn):int64_t;

    { Returns true if the stream has enough send capacity. }
    { }
    { On error a value lower than 0 is returned. }
    function quiche_conn_stream_writable(conn:Pquiche_conn; stream_id:uint64_t; len:size_t):longint;

    { Returns the next stream that can be written to, or -1 if no such stream is }
    { available. }
    function quiche_conn_stream_writable_next(conn:Pquiche_conn):int64_t;

    { Returns true if all the data has been read from the specified stream. }
(* Const before type ignored *)
    function quiche_conn_stream_finished(conn:Pquiche_conn; stream_id:uint64_t):bool;


    //type
    { Returns an iterator over streams that have outstanding data to read. }
(* Const before type ignored *)

    function quiche_conn_readable(conn:Pquiche_conn): Pquiche_stream_iter;

    { Returns an iterator over streams that can be written to. }
(* Const before type ignored *)
    function quiche_conn_writable(conn:Pquiche_conn): Pquiche_stream_iter;

    { Returns the maximum possible size of egress UDP payloads. }
(* Const before type ignored *)
    function quiche_conn_max_send_udp_payload_size(conn:Pquiche_conn):size_t;

    { Returns the amount of time until the next timeout event, in nanoseconds. }
(* Const before type ignored *)
    function quiche_conn_timeout_as_nanos(conn:Pquiche_conn):uint64_t;

    { Returns the amount of time until the next timeout event, in milliseconds. }
(* Const before type ignored *)
    function quiche_conn_timeout_as_millis(conn:Pquiche_conn):uint64_t;

    { Processes a timeout event. }
    procedure quiche_conn_on_timeout(conn:Pquiche_conn);

    { Closes the connection with the given error and reason. }
(* Const before type ignored *)
    function quiche_conn_close(conn:Pquiche_conn; app:bool; err:uint64_t; reason:Puint8_t; reason_len:size_t):longint;

    { Returns a string uniquely representing the connection. }
(* Const before type ignored *)
(* Const before type ignored *)
    procedure quiche_conn_trace_id(conn:Pquiche_conn; out_buffer:PPuint8_t; out_len:Psize_t);

    { Returns the source connection ID. }
(* Const before type ignored *)
(* Const before type ignored *)
    procedure quiche_conn_source_id(conn:Pquiche_conn; out_buffer:PPuint8_t; out_len:Psize_t);

    { Returns the destination connection ID. }
(* Const before type ignored *)
(* Const before type ignored *)
    procedure quiche_conn_destination_id(conn:Pquiche_conn; out_buffer:PPuint8_t; out_len:Psize_t);

    { Returns the negotiated ALPN protocol. }
(* Const before type ignored *)
(* Const before type ignored *)
    procedure quiche_conn_application_proto(conn:Pquiche_conn; out_buffer:PPuint8_t; out_len:Psize_t);

    { Returns the peer's leaf certificate (if any) as a DER-encoded buffer. }
(* Const before type ignored *)
(* Const before type ignored *)
    procedure quiche_conn_peer_cert(conn:Pquiche_conn; out_buffer:PPuint8_t; out_len:Psize_t);

    { Returns the serialized cryptographic session for the connection. }
(* Const before type ignored *)
(* Const before type ignored *)
    procedure quiche_conn_session(conn:Pquiche_conn; out_buffer:PPuint8_t; out_len:Psize_t);

    { Returns true if the connection handshake is complete. }
(* Const before type ignored *)
    function quiche_conn_is_established(conn:Pquiche_conn):bool;

    { Returns true if the connection has a pending handshake that has progressed }
    { enough to send or receive early data. }
(* Const before type ignored *)
    function quiche_conn_is_in_early_data(conn:Pquiche_conn):bool;

    { Returns whether there is stream or DATAGRAM data available to read. }
(* Const before type ignored *)
    function quiche_conn_is_readable(conn:Pquiche_conn):bool;

    { Returns true if the connection is draining. }
(* Const before type ignored *)
    function quiche_conn_is_draining(conn:Pquiche_conn):bool;

    { Returns the number of bidirectional streams that can be created }
    { before the peer's stream count limit is reached. }
(* Const before type ignored *)
    function quiche_conn_peer_streams_left_bidi(conn:Pquiche_conn):uint64_t;

    { Returns the number of unidirectional streams that can be created }
    { before the peer's stream count limit is reached. }
(* Const before type ignored *)
    function quiche_conn_peer_streams_left_uni(conn:Pquiche_conn):uint64_t;

    { Returns true if the connection is closed. }
(* Const before type ignored *)
    function quiche_conn_is_closed(conn:Pquiche_conn):bool;

    { Returns true if the connection was closed due to the idle timeout. }
(* Const before type ignored *)
    function quiche_conn_is_timed_out(conn:Pquiche_conn):bool;

    { Returns true if a connection error was received, and updates the provided }
    { parameters accordingly. }
(* Const before type ignored *)
(* Const before type ignored *)
    function quiche_conn_peer_error(conn:Pquiche_conn; is_app:Pbool; error_code:Puint64_t; reason:PPuint8_t; reason_len:Psize_t):bool;

    { Returns true if a connection error was queued or sent, and updates the provided }
    { parameters accordingly. }
(* Const before type ignored *)
(* Const before type ignored *)
    function quiche_conn_local_error(conn:Pquiche_conn; is_app:Pbool; error_code:Puint64_t; reason:PPuint8_t; reason_len:Psize_t):bool;

    { Fetches the next stream from the given iterator. Returns false if there are }
    { no more elements in the iterator. }
    function quiche_stream_iter_next(iter:Pquiche_stream_iter; stream_id:Puint64_t):bool;

    { Frees the given stream iterator object. }
    procedure quiche_stream_iter_free(iter:Pquiche_stream_iter);

    { The number of QUIC packets received on this connection. }
    { The number of QUIC packets sent on this connection. }
    { The number of QUIC packets that were lost. }
    { The number of sent QUIC packets with retransmitted data. }
    { The number of sent bytes. }
    { The number of received bytes. }
    { The number of bytes lost. }
    { The number of stream bytes retransmitted. }
    { The number of known paths for the connection. }

    { Collects and returns statistics about the connection. }
(* Const before type ignored *)

    procedure quiche_conn_stats(conn:Pquiche_conn; out_stat:Pquiche_stats);

    { The maximum idle timeout. }
    { The maximum UDP payload size. }
    { The initial flow control maximum data for the connection. }
    { The initial flow control maximum data for local bidirectional streams. }
    { The initial flow control maximum data for remote bidirectional streams. }
    { The initial flow control maximum data for unidirectional streams. }
    { The initial maximum bidirectional streams. }
    { The initial maximum unidirectional streams. }
    { The ACK delay exponent. }
    { The max ACK delay. }
    { Whether active migration is disabled. }
    { The active connection ID limit. }
    { DATAGRAM frame extension parameter, if any. }

    { Returns the peer's transport parameters in |out|. Returns false if we have }
    { not yet processed the peer's transport parameters. }
(* Const before type ignored *)

    function quiche_conn_peer_transport_params(conn:Pquiche_conn; out_params:Pquiche_transport_params):bool;

    { The local address used by this path. }
    { The peer address seen by this path. }
    { The validation state of the path. }
    { Whether this path is active. }
    { The number of QUIC packets received on this path. }
    { The number of QUIC packets sent on this path. }
    { The number of QUIC packets that were lost on this path. }
    { The number of sent QUIC packets with retransmitted data on this path. }
    { The estimated round-trip time of the path (in nanoseconds). }
    { The size of the path's congestion window in bytes. }
    { The number of sent bytes on this path. }
    { The number of received bytes on this path. }
    { The number of bytes lost on this path. }
    { The number of stream bytes retransmitted on this path. }
    { The current PMTU for the path. }
    { The most recent data delivery rate estimate in bytes/s. }

    { Collects and returns statistics about the specified path for the connection. }
    { }
    { The `idx` argument represent the path's index (also see the `paths_count` }
    { field of `quiche_stats`). }
(* Const before type ignored *)

    function quiche_conn_path_stats(conn:Pquiche_conn; idx:size_t; out_stat:Pquiche_path_stats):longint;

    { Returns whether or not this is a server-side connection. }
(* Const before type ignored *)
    function quiche_conn_is_server(conn:Pquiche_conn):bool;

    { Returns the maximum DATAGRAM payload that can be sent. }
(* Const before type ignored *)
    function quiche_conn_dgram_max_writable_len(conn:Pquiche_conn):ssize_t;

    { Returns the length of the first stored DATAGRAM. }
(* Const before type ignored *)
    function quiche_conn_dgram_recv_front_len(conn:Pquiche_conn):ssize_t;

    { Returns the number of items in the DATAGRAM receive queue. }
(* Const before type ignored *)
    function quiche_conn_dgram_recv_queue_len(conn:Pquiche_conn):ssize_t;

    { Returns the total size of all items in the DATAGRAM receive queue. }
(* Const before type ignored *)
    function quiche_conn_dgram_recv_queue_byte_size(conn:Pquiche_conn):ssize_t;

    { Returns the number of items in the DATAGRAM send queue. }
(* Const before type ignored *)
    function quiche_conn_dgram_send_queue_len(conn:Pquiche_conn):ssize_t;

    { Returns the total size of all items in the DATAGRAM send queue. }
(* Const before type ignored *)
    function quiche_conn_dgram_send_queue_byte_size(conn:Pquiche_conn):ssize_t;

    { Reads the first received DATAGRAM. }
    function quiche_conn_dgram_recv(conn:Pquiche_conn; buf:Puint8_t; buf_len:size_t):ssize_t;

    { Sends data in a DATAGRAM frame. }
(* Const before type ignored *)
    function quiche_conn_dgram_send(conn:Pquiche_conn; buf:Puint8_t; buf_len:size_t):ssize_t;

    { Purges queued outgoing DATAGRAMs matching the predicate. }
    procedure quiche_conn_dgram_purge_outgoing(conn:Pquiche_conn; f:TFunctionMatching);

    { Schedule an ack-eliciting packet on the active path. }
    function quiche_conn_send_ack_eliciting(conn:Pquiche_conn):ssize_t;

    { Schedule an ack-eliciting packet on the specified path. }
(* Const before type ignored *)
(* Const before type ignored *)
    function quiche_conn_send_ack_eliciting_on_path(conn:Pquiche_conn; local:Psockaddr; local_len:size_t; peer:Psockaddr; peer_len:size_t):ssize_t;

    { Frees the connection object. }
    procedure quiche_conn_free(conn:Pquiche_conn);

    { Writes an unsigned variable-length integer in network byte-order into }
    { the provided buffer. }
    function quiche_put_varint(buf:Puint8_t; buf_len:size_t; val:uint64_t):longint;

    { Reads an unsigned variable-length integer in network byte-order from }
    { the provided buffer and returns the wire length. }
(* Const before type ignored *)
    function quiche_get_varint(buf:Puint8_t; buf_len:size_t; val:uint64_t):ssize_t;

    { HTTP/3 API }
    { }
    { List of ALPN tokens of supported HTTP/3 versions. }
    const
      QUICHE_H3_APPLICATION_PROTOCOL = '\x02h3';      
    { There is no error or no work to do }
    { The provided buffer is too short. }
    { Internal error in the HTTP/3 stack. }
    { Endpoint detected that the peer is exhibiting behavior that causes. }
    { excessive load. }
    { Stream ID or Push ID greater that current maximum was }
    { used incorrectly, such as exceeding a limit, reducing a limit, }
    { or being reused. }
    { The endpoint detected that its peer created a stream that it will not }
    { accept. }
    { A required critical stream was closed. }
    { No SETTINGS frame at beginning of control stream. }
    { A frame was received which is not permitted in the current state. }
    { Frame violated layout or size rules. }
    { QPACK Header block decompression failure. }
    { -12 was previously used for TransportError, skip it }
    { The underlying QUIC stream (or connection) doesn't have enough capacity }
    { for the operation to complete. The application should retry later on. }
    { Error in the payload of a SETTINGS frame. }
    { Server rejected request. }
    { Request or its response cancelled. }
    { Client's request stream terminated without containing a full-formed }
    { request. }
    { An HTTP message was malformed and cannot be processed. }
    { The TCP connection established in response to a CONNECT request was }
    { reset or abnormally closed. }
    { The requested operation cannot be served over HTTP/3. Peer should retry }
    { over HTTP/1.1. }
    { The following QUICHE_H3_TRANSPORT_ERR_* errors are propagated }
    { from the QUIC transport layer. }
    { See QUICHE_ERR_DONE. }
    { See QUICHE_ERR_BUFFER_TOO_SHORT. }
    { See QUICHE_ERR_UNKNOWN_VERSION. }
    { See QUICHE_ERR_INVALID_FRAME. }
    { See QUICHE_ERR_INVALID_PACKET. }
    { See QUICHE_ERR_INVALID_STATE. }
    { See QUICHE_ERR_INVALID_STREAM_STATE. }
    { See QUICHE_ERR_INVALID_TRANSPORT_PARAM. }
    { See QUICHE_ERR_CRYPTO_FAIL. }
    { See QUICHE_ERR_TLS_FAIL. }
    { See QUICHE_ERR_FLOW_CONTROL. }
    { See QUICHE_ERR_STREAM_LIMIT. }
    { See QUICHE_ERR_STREAM_STOPPED. }
    { See QUICHE_ERR_STREAM_RESET. }
    { See QUICHE_ERR_FINAL_SIZE. }
    { See QUICHE_ERR_CONGESTION_CONTROL. }
    { See QUICHE_ERR_ID_LIMIT. }
    { See QUICHE_ERR_OUT_OF_IDENTIFIERS. }
    { See QUICHE_ERR_KEY_UPDATE. }

    type
      quiche_h3_error = (QUICHE_H3_ERR_DONE := -(1),QUICHE_H3_ERR_BUFFER_TOO_SHORT := -(2),
        QUICHE_H3_ERR_INTERNAL_ERROR := -(3),
        QUICHE_H3_ERR_EXCESSIVE_LOAD := -(4),
        QUICHE_H3_ERR_ID_ERROR := -(5),QUICHE_H3_ERR_STREAM_CREATION_ERROR := -(6),
        QUICHE_H3_ERR_CLOSED_CRITICAL_STREAM := -(7),
        QUICHE_H3_ERR_MISSING_SETTINGS := -(8),
        QUICHE_H3_ERR_FRAME_UNEXPECTED := -(9),
        QUICHE_H3_ERR_FRAME_ERROR := -(10),QUICHE_H3_ERR_QPACK_DECOMPRESSION_FAILED := -(11),
        QUICHE_H3_ERR_STREAM_BLOCKED := -(13),
        QUICHE_H3_ERR_SETTINGS_ERROR := -(14),
        QUICHE_H3_ERR_REQUEST_REJECTED := -(15),
        QUICHE_H3_ERR_REQUEST_CANCELLED := -(16),
        QUICHE_H3_ERR_REQUEST_INCOMPLETE := -(17),
        QUICHE_H3_ERR_MESSAGE_ERROR := -(18),
        QUICHE_H3_ERR_CONNECT_ERROR := -(19),
        QUICHE_H3_ERR_VERSION_FALLBACK := -(20),
        QUICHE_H3_TRANSPORT_ERR_DONE := QUICHE_ERR_DONE-1000,
        QUICHE_H3_TRANSPORT_ERR_BUFFER_TOO_SHORT := QUICHE_ERR_BUFFER_TOO_SHORT-1000,
        QUICHE_H3_TRANSPORT_ERR_UNKNOWN_VERSION := QUICHE_ERR_UNKNOWN_VERSION-1000,
        QUICHE_H3_TRANSPORT_ERR_INVALID_FRAME := QUICHE_ERR_INVALID_FRAME-1000,
        QUICHE_H3_TRANSPORT_ERR_INVALID_PACKET := QUICHE_ERR_INVALID_PACKET-1000,
        QUICHE_H3_TRANSPORT_ERR_INVALID_STATE := QUICHE_ERR_INVALID_STATE-1000,
        QUICHE_H3_TRANSPORT_ERR_INVALID_STREAM_STATE := QUICHE_ERR_INVALID_STREAM_STATE-1000,
        QUICHE_H3_TRANSPORT_ERR_INVALID_TRANSPORT_PARAM := QUICHE_ERR_INVALID_TRANSPORT_PARAM-1000,
        QUICHE_H3_TRANSPORT_ERR_CRYPTO_FAIL := QUICHE_ERR_CRYPTO_FAIL-1000,
        QUICHE_H3_TRANSPORT_ERR_TLS_FAIL := QUICHE_ERR_TLS_FAIL-1000,
        QUICHE_H3_TRANSPORT_ERR_FLOW_CONTROL := QUICHE_ERR_FLOW_CONTROL-1000,
        QUICHE_H3_TRANSPORT_ERR_STREAM_LIMIT := QUICHE_ERR_STREAM_LIMIT-1000,
        QUICHE_H3_TRANSPORT_ERR_STREAM_STOPPED := QUICHE_ERR_STREAM_STOPPED-1000,
        QUICHE_H3_TRANSPORT_ERR_STREAM_RESET := QUICHE_ERR_STREAM_RESET-1000,
        QUICHE_H3_TRANSPORT_ERR_FINAL_SIZE := QUICHE_ERR_FINAL_SIZE-1000,
        QUICHE_H3_TRANSPORT_ERR_CONGESTION_CONTROL := QUICHE_ERR_CONGESTION_CONTROL-1000,
        QUICHE_H3_TRANSPORT_ERR_ID_LIMIT := QUICHE_ERR_ID_LIMIT-1000,
        QUICHE_H3_TRANSPORT_ERR_OUT_OF_IDENTIFIERS := QUICHE_ERR_OUT_OF_IDENTIFIERS-1000,
        QUICHE_H3_TRANSPORT_ERR_KEY_UPDATE := QUICHE_ERR_KEY_UPDATE-1000
        );

    { Stores configuration shared between multiple connections. }
    { Creates an HTTP/3 config object with default settings values. }

    function quiche_h3_config_new:Pquiche_h3_config;

    { Sets the `SETTINGS_MAX_FIELD_SECTION_SIZE` setting. }
    procedure quiche_h3_config_set_max_field_section_size(config:Pquiche_h3_config; v:uint64_t);

    { Sets the `SETTINGS_QPACK_MAX_TABLE_CAPACITY` setting. }
    procedure quiche_h3_config_set_qpack_max_table_capacity(config:Pquiche_h3_config; v:uint64_t);

    { Sets the `SETTINGS_QPACK_BLOCKED_STREAMS` setting. }
    procedure quiche_h3_config_set_qpack_blocked_streams(config:Pquiche_h3_config; v:uint64_t);

    { Sets the `SETTINGS_ENABLE_CONNECT_PROTOCOL` setting. }
    procedure quiche_h3_config_enable_extended_connect(config:Pquiche_h3_config; enabled:bool);

    { Frees the HTTP/3 config object. }
    procedure quiche_h3_config_free(config:Pquiche_h3_config);

    { An HTTP/3 connection. }

    //type
    { Creates a new HTTP/3 connection using the provided QUIC connection. }

    function quiche_h3_conn_new_with_transport(quiche_conn:Pquiche_conn; config:Pquiche_h3_config):Pquiche_h3_conn;


    type
      quiche_h3_event_type = (QUICHE_H3_EVENT_HEADERS,QUICHE_H3_EVENT_DATA,
        QUICHE_H3_EVENT_FINISHED,QUICHE_H3_EVENT_GOAWAY,
        QUICHE_H3_EVENT_RESET,QUICHE_H3_EVENT_PRIORITY_UPDATE
        );

    { Processes HTTP/3 data received from the peer. }

    function quiche_h3_conn_poll(conn:Pquiche_h3_conn; quic_conn:Pquiche_conn; ev:PPquiche_h3_event):int64_t;

    { Returns the type of the event. }
(* error 
enum quiche_h3_event_type quiche_h3_event_type(quiche_h3_event *ev);
in declaration at line 861 *)
    { Iterates over the headers in the event. }
    { }
    { The `cb` callback will be called for each header in `ev`. `cb` should check }
    { the validity of pseudo-headers and headers. If `cb` returns any value other }
    { than `0`, processing will be interrupted and the value is returned to the }
    { caller. }
    function quiche_h3_event_for_each_header(ev:Pquiche_h3_event; cb:TFunctionCallbackCheck; argp:pointer):longint;

    { Iterates over the peer's HTTP/3 settings. }
    { }
    { The `cb` callback will be called for each setting in `conn`. }
    { If `cb` returns any value other than `0`, processing will be interrupted and }
    { the value is returned to the caller. }
    function quiche_h3_for_each_setting(conn:Pquiche_h3_conn; cb:TFunctionCallbackSettingCheck; argp:pointer):longint;

    { Check whether data will follow the headers on the stream. }
    function quiche_h3_event_headers_has_body(ev:Pquiche_h3_event):bool;

    { Check whether or not extended connection is enabled by the peer }
    function quiche_h3_extended_connect_enabled_by_peer(conn:Pquiche_h3_conn):bool;

    { Frees the HTTP/3 event object. }
    procedure quiche_h3_event_free(ev:Pquiche_h3_event);

(* Const before type ignored *)
(* Const before type ignored *)

    type
      quiche_h3_header = record
          name : ^uint8_t;
          name_len : size_t;
          value : ^uint8_t;
          value_len : size_t;
        end;
    { Extensible Priorities parameters. }

      quiche_h3_priority = record
          urgency : uint8_t;
          incremental : bool;
        end;
    { Sends an HTTP/3 request. }

    function quiche_h3_send_request(conn:Pquiche_h3_conn; quic_conn:Pquiche_conn; headers:Pquiche_h3_header; headers_len:size_t; fin:bool):int64_t;

    { Sends an HTTP/3 response on the specified stream with default priority. }
    function quiche_h3_send_response(conn:Pquiche_h3_conn; quic_conn:Pquiche_conn; stream_id:uint64_t; headers:Pquiche_h3_header; headers_len:size_t; 
               fin:bool):longint;

    { Sends an HTTP/3 response on the specified stream with specified priority. }
    function quiche_h3_send_response_with_priority(conn:Pquiche_h3_conn; quic_conn:Pquiche_conn; stream_id:uint64_t; headers:Pquiche_h3_header; headers_len:size_t; 
               priority:Pquiche_h3_priority; fin:bool):longint;

    { Sends an HTTP/3 body chunk on the given stream. }
    function quiche_h3_send_body(conn:Pquiche_h3_conn; quic_conn:Pquiche_conn; stream_id:uint64_t; body:Puint8_t; body_len:size_t; 
               fin:bool):ssize_t;

    { Reads request or response body data into the provided buffer. }
    function quiche_h3_recv_body(conn:Pquiche_h3_conn; quic_conn:Pquiche_conn; stream_id:uint64_t; out_buffer:Puint8_t; out_len:size_t):ssize_t;

    { Sends a GOAWAY frame to initiate graceful connection closure. }
    function quiche_h3_send_goaway(conn:Pquiche_h3_conn; quic_conn:Pquiche_conn; id:uint64_t):longint;

    { Try to parse an Extensible Priority field value. }
    function quiche_h3_parse_extensible_priority(priority:Puint8_t; priority_len:size_t; parsed:Pquiche_h3_priority):longint;

    {/ Sends a PRIORITY_UPDATE frame on the control stream with specified }
    {/ request stream ID and priority. }
    function quiche_h3_send_priority_update_for_request(conn:Pquiche_h3_conn; quic_conn:Pquiche_conn; stream_id:uint64_t; priority:Pquiche_h3_priority):longint;

    { Take the last received PRIORITY_UPDATE frame for a stream. }
    { }
    { The `cb` callback will be called once. `cb` should check the validity of }
    { priority field value contents. If `cb` returns any value other than `0`, }
    { processing will be interrupted and the value is returned to the caller. }
    function quiche_h3_take_last_priority_update(conn:Pquiche_h3_conn; prioritized_element_id:uint64_t; cb:function (priority_field_value:Puint8_t; priority_field_value_len:uint64_t; argp:pointer):longint; argp:pointer):longint;

    { Returns whether the peer enabled HTTP/3 DATAGRAM frame support. }
    function quiche_h3_dgram_enabled_by_peer(conn:Pquiche_h3_conn; quic_conn:Pquiche_conn):bool;

    { Frees the HTTP/3 connection object. }
    procedure quiche_h3_conn_free(conn:Pquiche_h3_conn);

{$if defined(__cplusplus)}
//(* error 
//}  // extern C
//    //{ extern C }
//{$endif}
{$endif}
    { QUICHE_H }

implementation

    function quiche_version:Pchar;
    begin
      { You must implement this function }
    end;
    function quiche_enable_debug_logging(cb:procedure (line:Pchar; argp:pointer); argp:pointer):longint;
    begin
      { You must implement this function }
    end;
    function quiche_config_new(version:uint32_t):Pquiche_config;
    begin
      { You must implement this function }
    end;
    function quiche_config_load_cert_chain_from_pem_file(config:Pquiche_config; path:Pchar):longint;
    begin
      { You must implement this function }
    end;
    function quiche_config_load_priv_key_from_pem_file(config:Pquiche_config; path:Pchar):longint;
    begin
      { You must implement this function }
    end;
    function quiche_config_load_verify_locations_from_file(config:Pquiche_config; path:Pchar):longint;
    begin
      { You must implement this function }
    end;
    function quiche_config_load_verify_locations_from_directory(config:Pquiche_config; path:Pchar):longint;
    begin
      { You must implement this function }
    end;
    procedure quiche_config_verify_peer(config:Pquiche_config; v:bool);
    begin
      { You must implement this function }
    end;
    procedure quiche_config_grease(config:Pquiche_config; v:bool);
    begin
      { You must implement this function }
    end;
    procedure quiche_config_log_keys(config:Pquiche_config);
    begin
      { You must implement this function }
    end;
    procedure quiche_config_enable_early_data(config:Pquiche_config);
    begin
      { You must implement this function }
    end;
    function quiche_config_set_application_protos(config:Pquiche_config; protos:Puint8_t; protos_len:size_t):longint;
    begin
      { You must implement this function }
    end;
    procedure quiche_config_set_max_idle_timeout(config:Pquiche_config; v:uint64_t);
    begin
      { You must implement this function }
    end;
    procedure quiche_config_set_max_recv_udp_payload_size(config:Pquiche_config; v:size_t);
    begin
      { You must implement this function }
    end;
    procedure quiche_config_set_max_send_udp_payload_size(config:Pquiche_config; v:size_t);
    begin
      { You must implement this function }
    end;
    procedure quiche_config_set_initial_max_data(config:Pquiche_config; v:uint64_t);
    begin
      { You must implement this function }
    end;
    procedure quiche_config_set_initial_max_stream_data_bidi_local(config:Pquiche_config; v:uint64_t);
    begin
      { You must implement this function }
    end;
    procedure quiche_config_set_initial_max_stream_data_bidi_remote(config:Pquiche_config; v:uint64_t);
    begin
      { You must implement this function }
    end;
    procedure quiche_config_set_initial_max_stream_data_uni(config:Pquiche_config; v:uint64_t);
    begin
      { You must implement this function }
    end;
    procedure quiche_config_set_initial_max_streams_bidi(config:Pquiche_config; v:uint64_t);
    begin
      { You must implement this function }
    end;
    procedure quiche_config_set_initial_max_streams_uni(config:Pquiche_config; v:uint64_t);
    begin
      { You must implement this function }
    end;
    procedure quiche_config_set_ack_delay_exponent(config:Pquiche_config; v:uint64_t);
    begin
      { You must implement this function }
    end;
    procedure quiche_config_set_max_ack_delay(config:Pquiche_config; v:uint64_t);
    begin
      { You must implement this function }
    end;
    procedure quiche_config_set_disable_active_migration(config:Pquiche_config; v:bool);
    begin
      { You must implement this function }
    end;
    function quiche_config_set_cc_algorithm_name(config:Pquiche_config; algo:Pchar):longint;
    begin
      { You must implement this function }
    end;
    procedure quiche_config_set_initial_congestion_window_packets(config:Pquiche_config; packets:size_t);
    begin
      { You must implement this function }
    end;
    procedure quiche_config_set_cc_algorithm(config:Pquiche_config; algo:quiche_cc_algorithm);
    begin
      { You must implement this function }
    end;
    procedure quiche_config_enable_hystart(config:Pquiche_config; v:bool);
    begin
      { You must implement this function }
    end;
    procedure quiche_config_enable_pacing(config:Pquiche_config; v:bool);
    begin
      { You must implement this function }
    end;
    procedure quiche_config_set_max_pacing_rate(config:Pquiche_config; v:uint64_t);
    begin
      { You must implement this function }
    end;
    procedure quiche_config_enable_dgram(config:Pquiche_config; enabled:bool; recv_queue_len:size_t; send_queue_len:size_t);
    begin
      { You must implement this function }
    end;
    procedure quiche_config_set_max_connection_window(config:Pquiche_config; v:uint64_t);
    begin
      { You must implement this function }
    end;
    procedure quiche_config_set_max_stream_window(config:Pquiche_config; v:uint64_t);
    begin
      { You must implement this function }
    end;
    procedure quiche_config_set_active_connection_id_limit(config:Pquiche_config; v:uint64_t);
    begin
      { You must implement this function }
    end;
    procedure quiche_config_set_stateless_reset_token(config:Pquiche_config; v:Puint8_t);
    begin
      { You must implement this function }
    end;
    procedure quiche_config_free(config:Pquiche_config);
    begin
      { You must implement this function }
    end;
    function quiche_header_info(buf:Puint8_t; buf_len:size_t; dcil:size_t; version:Puint32_t; _type:Puint8_t; 
               scid:Puint8_t; scid_len:Psize_t; dcid:Puint8_t; dcid_len:Psize_t; token:Puint8_t; 
               token_len:Psize_t):longint;
    begin
      { You must implement this function }
    end;
    function quiche_accept(scid:Puint8_t; scid_len:size_t; odcid:Puint8_t; odcid_len:size_t; local:Psockaddr; 
               local_len:size_t; peer:Psockaddr; peer_len:size_t; config:Pquiche_config):Pquiche_conn;
    begin
      { You must implement this function }
    end;
    function quiche_connect(server_name:Pchar; scid:Puint8_t; scid_len:size_t; local:Psockaddr; local_len:size_t; 
               peer:Psockaddr; peer_len:size_t; config:Pquiche_config):Pquiche_conn;
    begin
      { You must implement this function }
    end;
    function quiche_negotiate_version(scid:Puint8_t; scid_len:size_t; dcid:Puint8_t; dcid_len:size_t; out_buffer:Puint8_t; 
               out_len:size_t):ssize_t;
    begin
      { You must implement this function }
    end;
    function quiche_retry(scid:Puint8_t; scid_len:size_t; dcid:Puint8_t; dcid_len:size_t; new_scid:Puint8_t; 
               new_scid_len:size_t; token:Puint8_t; token_len:size_t; version:uint32_t; out_buffer:Puint8_t;
               out_len:size_t):ssize_t;
    begin
      { You must implement this function }
    end;
    function quiche_version_is_supported(version:uint32_t):bool;
    begin
      { You must implement this function }
    end;
    function quiche_conn_new_with_tls(scid:Puint8_t; scid_len:size_t; odcid:Puint8_t; odcid_len:size_t; local:Psockaddr; 
               local_len:size_t; peer:Psockaddr; peer_len:size_t; config:Pquiche_config; ssl:pointer; 
               is_server:bool):Pquiche_conn;
    begin
      { You must implement this function }
    end;
    function quiche_conn_set_keylog_path(conn:Pquiche_conn; path:Pchar):bool;
    begin
      { You must implement this function }
    end;
    procedure quiche_conn_set_keylog_fd(conn:Pquiche_conn; fd:longint);
    begin
      { You must implement this function }
    end;
    function quiche_conn_set_qlog_path(conn:Pquiche_conn; path:Pchar; log_title:Pchar; log_desc:Pchar):bool;
    begin
      { You must implement this function }
    end;
    procedure quiche_conn_set_qlog_fd(conn:Pquiche_conn; fd:longint; log_title:Pchar; log_desc:Pchar);
    begin
      { You must implement this function }
    end;
    function quiche_conn_set_session(conn:Pquiche_conn; buf:Puint8_t; buf_len:size_t):longint;
    begin
      { You must implement this function }
    end;
    function quiche_conn_recv(conn:Pquiche_conn; buf:Puint8_t; buf_len:size_t; info:Pquiche_recv_info):ssize_t;
    begin
      { You must implement this function }
    end;
    function quiche_conn_send(conn:Pquiche_conn; out_buffer:Puint8_t; out_len:size_t; out_info:Pquiche_send_info):ssize_t;
    begin
      { You must implement this function }
    end;
    function quiche_conn_send_quantum(conn:Pquiche_conn):size_t;
    begin
      { You must implement this function }
    end;
    function quiche_conn_stream_recv(conn:Pquiche_conn; stream_id:uint64_t; out_buffer:Puint8_t; buf_len:size_t; fin:Pbool):ssize_t;
    begin
      { You must implement this function }
    end;
    function quiche_conn_stream_send(conn:Pquiche_conn; stream_id:uint64_t; buf:Puint8_t; buf_len:size_t; fin:bool):ssize_t;
    begin
      { You must implement this function }
    end;
    function quiche_conn_stream_priority(conn:Pquiche_conn; stream_id:uint64_t; urgency:uint8_t; incremental:bool):longint;
    begin
      { You must implement this function }
    end;
    function quiche_conn_stream_shutdown(conn:Pquiche_conn; stream_id:uint64_t; direction:quiche_shutdown; err:uint64_t):longint;
    begin
      { You must implement this function }
    end;
    function quiche_conn_stream_capacity(conn:Pquiche_conn; stream_id:uint64_t):ssize_t;
    begin
      { You must implement this function }
    end;
    function quiche_conn_stream_readable(conn:Pquiche_conn; stream_id:uint64_t):bool;
    begin
      { You must implement this function }
    end;
    function quiche_conn_stream_readable_next(conn:Pquiche_conn):int64_t;
    begin
      { You must implement this function }
    end;
    function quiche_conn_stream_writable(conn:Pquiche_conn; stream_id:uint64_t; len:size_t):longint;
    begin
      { You must implement this function }
    end;
    function quiche_conn_stream_writable_next(conn:Pquiche_conn):int64_t;
    begin
      { You must implement this function }
    end;
    function quiche_conn_stream_finished(conn:Pquiche_conn; stream_id:uint64_t):bool;
    begin
      { You must implement this function }
    end;
    function quiche_conn_readable(conn:Pquiche_conn):Pquiche_stream_iter;
    begin
      { You must implement this function }
    end;
    function quiche_conn_writable(conn:Pquiche_conn):Pquiche_stream_iter;
    begin
      { You must implement this function }
    end;
    function quiche_conn_max_send_udp_payload_size(conn:Pquiche_conn):size_t;
    begin
      { You must implement this function }
    end;
    function quiche_conn_timeout_as_nanos(conn:Pquiche_conn):uint64_t;
    begin
      { You must implement this function }
    end;
    function quiche_conn_timeout_as_millis(conn:Pquiche_conn):uint64_t;
    begin
      { You must implement this function }
    end;
    procedure quiche_conn_on_timeout(conn:Pquiche_conn);
    begin
      { You must implement this function }
    end;
    function quiche_conn_close(conn:Pquiche_conn; app:bool; err:uint64_t; reason:Puint8_t; reason_len:size_t):longint;
    begin
      { You must implement this function }
    end;
    procedure quiche_conn_trace_id(conn:Pquiche_conn; out_buffer:PPuint8_t; out_len:Psize_t);
    begin
      { You must implement this function }
    end;
    procedure quiche_conn_source_id(conn:Pquiche_conn; out_buffer:PPuint8_t; out_len:Psize_t);
    begin
      { You must implement this function }
    end;
    procedure quiche_conn_destination_id(conn:Pquiche_conn; out_buffer:PPuint8_t; out_len:Psize_t);
    begin
      { You must implement this function }
    end;
    procedure quiche_conn_application_proto(conn:Pquiche_conn; out_buffer:PPuint8_t; out_len:Psize_t);
    begin
      { You must implement this function }
    end;
    procedure quiche_conn_peer_cert(conn:Pquiche_conn; out_buffer:PPuint8_t; out_len:Psize_t);
    begin
      { You must implement this function }
    end;
    procedure quiche_conn_session(conn:Pquiche_conn; out_buffer:PPuint8_t; out_len:Psize_t);
    begin
      { You must implement this function }
    end;
    function quiche_conn_is_established(conn:Pquiche_conn):bool;
    begin
      { You must implement this function }
    end;
    function quiche_conn_is_in_early_data(conn:Pquiche_conn):bool;
    begin
      { You must implement this function }
    end;
    function quiche_conn_is_readable(conn:Pquiche_conn):bool;
    begin
      { You must implement this function }
    end;
    function quiche_conn_is_draining(conn:Pquiche_conn):bool;
    begin
      { You must implement this function }
    end;
    function quiche_conn_peer_streams_left_bidi(conn:Pquiche_conn):uint64_t;
    begin
      { You must implement this function }
    end;
    function quiche_conn_peer_streams_left_uni(conn:Pquiche_conn):uint64_t;
    begin
      { You must implement this function }
    end;
    function quiche_conn_is_closed(conn:Pquiche_conn):bool;
    begin
      { You must implement this function }
    end;
    function quiche_conn_is_timed_out(conn:Pquiche_conn):bool;
    begin
      { You must implement this function }
    end;
    function quiche_conn_peer_error(conn:Pquiche_conn; is_app:Pbool; error_code:Puint64_t; reason:PPuint8_t; reason_len:Psize_t):bool;
    begin
      { You must implement this function }
    end;
    function quiche_conn_local_error(conn:Pquiche_conn; is_app:Pbool; error_code:Puint64_t; reason:PPuint8_t; reason_len:Psize_t):bool;
    begin
      { You must implement this function }
    end;
    function quiche_stream_iter_next(iter:Pquiche_stream_iter; stream_id:Puint64_t):bool;
    begin
      { You must implement this function }
    end;
    procedure quiche_stream_iter_free(iter:Pquiche_stream_iter);
    begin
      { You must implement this function }
    end;
    procedure quiche_conn_stats(conn:Pquiche_conn; out_stat:Pquiche_stats);
    begin
      { You must implement this function }
    end;
    function quiche_conn_peer_transport_params(conn:Pquiche_conn; out_params:Pquiche_transport_params):bool;
    begin
      { You must implement this function }
    end;
    function quiche_conn_path_stats(conn:Pquiche_conn; idx:size_t; out_stat:Pquiche_path_stats):longint;
    begin
      { You must implement this function }
    end;
    function quiche_conn_is_server(conn:Pquiche_conn):bool;
    begin
      { You must implement this function }
    end;
    function quiche_conn_dgram_max_writable_len(conn:Pquiche_conn):ssize_t;
    begin
      { You must implement this function }
    end;
    function quiche_conn_dgram_recv_front_len(conn:Pquiche_conn):ssize_t;
    begin
      { You must implement this function }
    end;
    function quiche_conn_dgram_recv_queue_len(conn:Pquiche_conn):ssize_t;
    begin
      { You must implement this function }
    end;
    function quiche_conn_dgram_recv_queue_byte_size(conn:Pquiche_conn):ssize_t;
    begin
      { You must implement this function }
    end;
    function quiche_conn_dgram_send_queue_len(conn:Pquiche_conn):ssize_t;
    begin
      { You must implement this function }
    end;
    function quiche_conn_dgram_send_queue_byte_size(conn:Pquiche_conn):ssize_t;
    begin
      { You must implement this function }
    end;
    function quiche_conn_dgram_recv(conn:Pquiche_conn; buf:Puint8_t; buf_len:size_t):ssize_t;
    begin
      { You must implement this function }
    end;
    function quiche_conn_dgram_send(conn:Pquiche_conn; buf:Puint8_t; buf_len:size_t):ssize_t;
    begin
      { You must implement this function }
    end;
    procedure quiche_conn_dgram_purge_outgoing(conn:Pquiche_conn; f:function (_para1:Puint8_t; _para2:size_t):bool);
    begin
      { You must implement this function }
    end;
    function quiche_conn_send_ack_eliciting(conn:Pquiche_conn):ssize_t;
    begin
      { You must implement this function }
    end;
    function quiche_conn_send_ack_eliciting_on_path(conn:Pquiche_conn; local:Psockaddr; local_len:size_t; peer:Psockaddr; peer_len:size_t):ssize_t;
    begin
      { You must implement this function }
    end;
    procedure quiche_conn_free(conn:Pquiche_conn);
    begin
      { You must implement this function }
    end;
    function quiche_put_varint(buf:Puint8_t; buf_len:size_t; val:uint64_t):longint;
    begin
      { You must implement this function }
    end;
    function quiche_get_varint(buf:Puint8_t; buf_len:size_t; val:uint64_t):ssize_t;
    begin
      { You must implement this function }
    end;
    function quiche_h3_config_new:Pquiche_h3_config;
    begin
      { You must implement this function }
    end;
    procedure quiche_h3_config_set_max_field_section_size(config:Pquiche_h3_config; v:uint64_t);
    begin
      { You must implement this function }
    end;
    procedure quiche_h3_config_set_qpack_max_table_capacity(config:Pquiche_h3_config; v:uint64_t);
    begin
      { You must implement this function }
    end;
    procedure quiche_h3_config_set_qpack_blocked_streams(config:Pquiche_h3_config; v:uint64_t);
    begin
      { You must implement this function }
    end;
    procedure quiche_h3_config_enable_extended_connect(config:Pquiche_h3_config; enabled:bool);
    begin
      { You must implement this function }
    end;
    procedure quiche_h3_config_free(config:Pquiche_h3_config);
    begin
      { You must implement this function }
    end;
    function quiche_h3_conn_new_with_transport(quiche_conn:Pquiche_conn; config:Pquiche_h3_config):Pquiche_h3_conn;
    begin
      { You must implement this function }
    end;
    function quiche_h3_conn_poll(conn:Pquiche_h3_conn; quic_conn:Pquiche_conn; ev:PPquiche_h3_event):int64_t;
    begin
      { You must implement this function }
    end;
    function quiche_h3_event_for_each_header(ev:Pquiche_h3_event; cb:function (name:Puint8_t; name_len:size_t; value:Puint8_t; value_len:size_t; argp:pointer):longint; argp:pointer):longint;
    begin
      { You must implement this function }
    end;
    function quiche_h3_for_each_setting(conn:Pquiche_h3_conn; cb:function (identifier:uint64_t; value:uint64_t; argp:pointer):longint; argp:pointer):longint;
    begin
      { You must implement this function }
    end;
    function quiche_h3_event_headers_has_body(ev:Pquiche_h3_event):bool;
    begin
      { You must implement this function }
    end;
    function quiche_h3_extended_connect_enabled_by_peer(conn:Pquiche_h3_conn):bool;
    begin
      { You must implement this function }
    end;
    procedure quiche_h3_event_free(ev:Pquiche_h3_event);
    begin
      { You must implement this function }
    end;
    function quiche_h3_send_request(conn:Pquiche_h3_conn; quic_conn:Pquiche_conn; headers:Pquiche_h3_header; headers_len:size_t; fin:bool):int64_t;
    begin
      { You must implement this function }
    end;
    function quiche_h3_send_response(conn:Pquiche_h3_conn; quic_conn:Pquiche_conn; stream_id:uint64_t; headers:Pquiche_h3_header; headers_len:size_t; 
               fin:bool):longint;
    begin
      { You must implement this function }
    end;
    function quiche_h3_send_response_with_priority(conn:Pquiche_h3_conn; quic_conn:Pquiche_conn; stream_id:uint64_t; headers:Pquiche_h3_header; headers_len:size_t; 
               priority:Pquiche_h3_priority; fin:bool):longint;
    begin
      { You must implement this function }
    end;
    function quiche_h3_send_body(conn:Pquiche_h3_conn; quic_conn:Pquiche_conn; stream_id:uint64_t; body:Puint8_t; body_len:size_t; 
               fin:bool):ssize_t;
    begin
      { You must implement this function }
    end;
    function quiche_h3_recv_body(conn:Pquiche_h3_conn; quic_conn:Pquiche_conn; stream_id:uint64_t; out_buffer:Puint8_t; out_len:size_t):ssize_t;
    begin
      { You must implement this function }
    end;
    function quiche_h3_send_goaway(conn:Pquiche_h3_conn; quic_conn:Pquiche_conn; id:uint64_t):longint;
    begin
      { You must implement this function }
    end;
    function quiche_h3_parse_extensible_priority(priority:Puint8_t; priority_len:size_t; parsed:Pquiche_h3_priority):longint;
    begin
      { You must implement this function }
    end;
    function quiche_h3_send_priority_update_for_request(conn:Pquiche_h3_conn; quic_conn:Pquiche_conn; stream_id:uint64_t; priority:Pquiche_h3_priority):longint;
    begin
      { You must implement this function }
    end;
    function quiche_h3_take_last_priority_update(conn:Pquiche_h3_conn; prioritized_element_id:uint64_t; cb:function (priority_field_value:Puint8_t; priority_field_value_len:uint64_t; argp:pointer):longint; argp:pointer):longint;
    begin
      { You must implement this function }
    end;
    function quiche_h3_dgram_enabled_by_peer(conn:Pquiche_h3_conn; quic_conn:Pquiche_conn):bool;
    begin
      { You must implement this function }
    end;
    procedure quiche_h3_conn_free(conn:Pquiche_h3_conn);
    begin
      { You must implement this function }
    end;


end.
