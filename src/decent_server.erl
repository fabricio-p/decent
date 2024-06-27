%%%-------------------------------------------------------------------
%% @doc the genserver that handles the messaging etc.
%% @end
%%%-------------------------------------------------------------------

-module(decent_server).

-behaviour(gen_server).

-include("decent_protocol.hrl").

%% callback for starting the process.

-export([start_link/0]).

%% process interface functions.

-export(
    [
        default_port/0,
        open_socket/1,
        send_data/1,
        send_data/3,
        connect_to/2,
        assign_room_key/1
    ]
).

%% internal gen_server callbacks. DO NOT CALL DIRECTLY!

-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2]).

%% INTERFACE -------------------------------------------------------------------

start_link() ->
    case gen_server:start_link({local, ?MODULE}, ?MODULE, [], []) of
        {ok, Pid} ->
            % process_flag(Pid, message_queue_data, off_heap),
            {ok, Pid};

        Error -> Error
    end.

-define(PORT, 4011).

default_port() -> ?PORT.

open_socket(Port) -> gen_server:call(?MODULE, {open_socket, Port}).

-spec send_data(iodata()) -> ok.

%% Send a chunk of data to all contacts.

send_data(Data) -> gen_server:cast(?MODULE, {send_data, Data}).

-spec send_data(iodata(), inet:ip_address(), inet:port_number()) -> ok.

%% Send a chunk of data to the contact with ip Ip at port Port.

send_data(Data, Ip, Port) ->
    gen_server:cast(?MODULE, {send_data, Data, Ip, Port}).

-spec connect_to(inet:ip_address(), inet:port_number()) -> ok.
connect_to(Ip, Port) -> gen_server:cast(?MODULE, {connect_to, Ip, Port}).

-spec assign_room_key(binary()) -> ok.
assign_room_key(RoomKey) ->
    gen_server:cast(?MODULE, {assign_room_key, RoomKey}).

%% gen_server internals --------------------------------------------------------

-type contact_addr() :: {inet:ip_address(), inet:port_number()}.

-record(contact, {pid :: pid()}).

-type contact() :: #contact{}.

% -record(conn_req, {pub_key :: binary()}).
-record(
    state,
    {
        contacts = #{} :: #{contact_addr() => contact()},
        port = 0 :: inet:port_number(),
        socket = nil :: nil | inet:socket(),
        room = nil :: nil | {roomkey, binary()}
    }
).

-type state() :: #state{}.

-spec init(any()) -> {ok, state()}.
init(_Args) -> {ok, #state{}}.

%% Opens a UDP socket on the specified port

handle_call({open_socket, Port}, _From, #state{socket = nil} = State) ->
    {ok, Socket} = gen_udp:open(Port, [binary, {active, true}]),
    {reply, ok, State#state{port = Port, socket = Socket}};

%% If the socket is already open on the specified port, nothing happens
handle_call({open_socket, Port}, _From, #state{port = Port} = State) ->
    {reply, ok, State};

%% If the socket is open on a different port, the old socket is closed and a new one is opened on the specified port
handle_call({open_socket, Port}, _From, #state{socket = OldSocket} = State) ->
    Result = gen_udp:close(OldSocket),
    {ok, Socket} = gen_udp:open(Port, [binary, {active, true}]),
    {reply, Result, State#state{port = Port, socket = Socket}}.

%% Sends a message to all contacts

handle_cast(
    {send_data, Content},
    #state{contacts = Contacts, socket = Socket, room = {roomkey, Key}} = State
) ->
    % NOTE: Maybe mode this to another cast thing, send data is for raw data imo
    InnerPacket = #text_packet{content = Content},
    SerializedInnerPacket = decent_protocol:serialize_packet(InnerPacket),
    {Nonce, Enc, Tag} = decent_crypto:encrypt_data(SerializedInnerPacket, Key),
    Packet = #encrypted{nonce = Nonce, tag = Tag, data = Enc},
    SerializedPacket = decent_protocol:serialize_packet(Packet),
    maps:foreach(
        fun
            ({Ip, Port}, #contact{pid = _Pid}) ->
                gen_udp:send(Socket, Ip, Port, SerializedPacket)
        end,
        Contacts
    ),
    {noreply, State};

%% Sends data to the specified ip and port
handle_cast({send_data, Data, Ip, Port}, #state{socket = Socket} = State) ->
    gen_udp:send(Socket, Ip, Port, Data),
    {noreply, State};

%% Connects to and establishes contact with the specified ip and port
handle_cast(
    {connect_to, Ip, Port},
    #state{contacts = Contacts, room = RoomKey} = State
) ->
    HasConnection = maps:is_key({Ip, Port}, Contacts),
    NewContacts =
        if
            HasConnection -> Contacts;

            true ->
                {Pid, NewContacts_} =
                    spawn_contact_worker(Ip, Port, RoomKey, Contacts),
                decent_worker:try_connect(Pid),
                NewContacts_
        end,
    {noreply, State#state{contacts = NewContacts}};

%% Assigns a global room key
handle_cast({assign_room_key, RoomKey}, #state{room = nil} = State) ->
    {noreply, State#state{room = {roomkey, RoomKey}}};

%% Ignores the new room key if a room key is already assigned.
handle_cast({assign_room_key, _RoomKey}, #state{room = _OldRoomKey} = State) ->
    {noreply, State}.


handle_info({'DOWN', _Ref, process, _Pid, normal}, State) -> {noreply, State};
%% Removes the ip and port from the contacts map
handle_info(
    {'DOWN', _Ref, process, _Pid, {disconnect, Ip, Port}},
    #state{contacts = Contacts} = State
) ->
    NewContacts = maps:remove({Ip, Port}, Contacts),
    {noreply, State#state{contacts = NewContacts}};

%% Processes a UDP message
handle_info(
    {udp, _Socket, SrcIp, SrcPort, Data},
    #state{contacts = Contacts, room = RoomKey} = State
) ->
    {Pid, NewContacts} = process_udp_packet(SrcIp, SrcPort, RoomKey, Contacts),
    decent_worker:handle_packet(Pid, Data),
    {noreply, State#state{contacts = NewContacts}}.

%% Terminates the server

terminate(_Reason, #state{socket = Socket, contacts = Contacts}) ->
    if Socket =/= nil -> gen_udp:close(Socket) end,
    kill_contact_workers(Contacts),
    ok.

%% Internal private functions --------------------------------------------------
%% Processes a UDP packet and either creates a new contact worker or retrieves
%% an existing one

process_udp_packet(Ip, Port, RoomKey, Contacts) ->
    case maps:get({Ip, Port}, Contacts, nil) of
        nil -> spawn_contact_worker(Ip, Port, RoomKey, Contacts);
        #contact{pid = Pid} -> {Pid, Contacts}
    end.


spawn_contact_worker(Ip, Port, RoomKey, Contacts) ->
    {ok, Pid} = decent_worker:start_link({Ip, Port, RoomKey}),
    NewContacts = maps:put({Ip, Port}, #contact{pid = Pid}, Contacts),
    {Pid, NewContacts}.


kill_contact_workers(Contacts) ->
    maps:foreach(
        fun (_Addr, #contact{pid = Pid}) -> exit(Pid, normal) end,
        Contacts
    ),
    ok.

%% -----------------------------------------------------------------------------
