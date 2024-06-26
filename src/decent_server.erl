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
-export([default_port/0,
         open_socket/1,
         close_socket/0,
         send_data/1,
         send_data/3,
         connect_to/2,
         assign_secret/1,
        request_worker/2]).

%% internal gen_server callbacks. DO NOT CALL DIRECTLY!

-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2]).

%% INTERFACE -------------------------------------------------------------------

start_link() ->
    case gen_server:start_link({local, ?MODULE}, ?MODULE, [], []) of
        {ok, Pid} ->
            % process_flag(Pid, message_queue_data, off_heap),
            {ok, Pid};

        Error ->
            Error
    end.

-define(PORT, 4011).

default_port() ->
    ?PORT.

open_socket(Port) -> gen_server:call(?MODULE, {open_socket, Port}).

close_socket() -> gen_server:call(?MODULE, close_socket).

-spec send_data(iodata()) -> ok.

%% Send a chunk of data to all contacts.

send_data(Data) -> gen_server:cast(?MODULE, {send_data, Data}).

-spec send_data(iodata(), inet:ip_address(), inet:port_number()) -> ok.

%% Send a chunk of data to the contact with ip Ip at port Port.

send_data(Data, Ip, Port) ->
    gen_server:cast(?MODULE, {send_data, Data, Ip, Port}).

-spec connect_to(inet:ip_address(), inet:port_number()) -> ok.
connect_to(Ip, Port) -> gen_server:cast(?MODULE, {connect_to, Ip, Port}).

-spec assign_secret(binary()) -> ok.
assign_secret(Secret) -> gen_server:cast(?MODULE, {assign_secret, Secret}).

-spec request_worker(inet:ip_address(), inet:port_number()) -> ok.
request_worker(Ip, Port) ->
    gen_server:call(?MODULE, {request_worker, Ip, Port}).

%% gen_server internals --------------------------------------------------------

-type contact_addr() :: {inet:ip_address(), inet:port_number()}.

-record(contact, {pid :: pid()}).

-type contact() :: #contact{}.

% -record(conn_req, {pub_key :: binary()}).

-record(state, {contacts = #{} :: #{contact_addr() => contact()},
                port = 0       :: inet:port_number(),
                socket = nil   :: nil | inet:socket(),
                secret = nil   :: nil | {shared, binary()}}).

-type state() :: #state{}.

-spec init(any()) -> {ok, state()}.
init(_Args) -> {ok, #state{}}.

handle_call({open_socket, Port}, _From, #state{socket = nil} = State) ->
    {ok, Socket} = gen_udp:open(Port, [binary, {active, true}]),
    {reply, ok, State#state{port = Port, socket = Socket}};
handle_call({open_socket, Port}, _From, #state{port = Port} = State) ->
    {reply, ok, State};
handle_call({open_socket, Port}, _From, #state{socket = OldSocket} = State) ->
    Result = gen_udp:close(OldSocket),
    {ok, Socket} = gen_udp:open(Port, [binary, {active, true}]),
    {reply, Result, State#state{port = Port, socket = Socket}};
handle_call(close_socket, _From, #state{socket = Socket} = State)
  when Socket =/= nil ->
    % NOTE: Maybe we should kill the contact workers
    {noreply, gen_udp:close(Socket), State#state{port = 0, socket = nil}};
handle_call(close_socket, _From, #state{socket = nil} = State) ->
    {reply, ok, State};

handle_call(
  {request_worker, Ip, Port},
  _From,
  #state{contacts = Contacts} = State
 ) ->
    % {Reply, NewContacts} =
    %     case maps:get({Ip, Port}, Contacts, nil) of
    %         nil ->
    %             {{error, enoent}, Contacts};
    %         #contact{pid = Pid} = Contact ->
    %             NewContacts_ = maps:put({Ip, Port}, Contact#contact{ owner = })
    Reply =
        case maps:get({Ip, Port}, Contacts, nil) of
            nil -> {error, enoent};

            #contact{pid = Pid} -> {ok, Pid}
        end,
    {reply, Reply, State}.

handle_cast(
  {send_data, Content},
  #state{contacts = Contacts, socket = _Socket, secret = {shared, Key}} = State
 ) ->
    {Nonce, Enc, Tag} = decent_crypto:encrypt_data(Content, Key),
    Packet = #encrypted{nonce = Nonce, tag = Tag, data = Enc},
    SerializedPacket = decent_protocol:serialize_packet(Packet),
    % plenty
    maps:foreach(
      fun(_Key, #contact{pid = Pid}) ->
              decent_worker:send_message(Pid, SerializedPacket)
      end,
      Contacts),

    {noreply, State};
handle_cast({send_data, Data, Ip, Port}, #state{socket = Socket} = State) ->
    gen_udp:send(Socket, Ip, Port, Data),
    {noreply, State};

handle_cast({connect_to, Ip, Port}, #state{contacts = Contacts, secret = Secret} = State) ->
    HasConnection = maps:is_key({Ip, Port}, Contacts),
    NewContacts =
        if
            HasConnection ->
                Contacts;
            true ->
                {Pid, NewContacts_} = spawn_contact_worker(Ip, Port, Secret, Contacts),
                decent_worker:try_connect(Pid),
                NewContacts_
        end,
    {noreply, State#state{contacts = NewContacts}};

handle_cast({assign_secret, Secret}, #state{ secret = nil } = State) -> 
    {noreply, State#state{ secret = {shared, Secret} }};

handle_cast({assign_secret, _Secret}, #state{ secret = _OldSecret } = State) -> 
    {noreply, State}.

handle_info({'DOWN', _Ref, process, _Pid, normal}, State) ->
    {noreply, State};

handle_info(
  {'DOWN', _Ref, process, _Pid, {disconnect, Ip, Port}},
  #state{contacts = Contacts} = State
 ) ->
    NewContacts = maps:remove({Ip, Port}, Contacts),
    {noreply, State#state{contacts = NewContacts}};

handle_info(
  {udp, _Socket, SrcIp, SrcPort, Data},
  #state{contacts = Contacts, secret = Secret} = State
) ->
    {Pid, NewContacts} = process_udp_packet(SrcIp, SrcPort, Secret, Contacts),
    decent_worker:message(Pid, Data),
    {noreply, State#state{contacts = NewContacts}}.


terminate(_Reason, #state{socket = Socket, contacts = Contacts}) ->
    if Socket =/= nil ->
            gen_udp:close(Socket)
    end,
    kill_contact_workers(Contacts),
    ok.

%% Internal private functions --------------------------------------------------

process_udp_packet(Ip, Port, Secret, Contacts) ->
    case maps:get({Ip, Port}, Contacts, nil) of
        nil ->
            spawn_contact_worker(Ip, Port, Secret, Contacts);

        #contact{pid = Pid} ->
            {Pid, Contacts}
    end.


spawn_contact_worker(Ip, Port, Secret, Contacts) ->
    {ok, Pid} = decent_worker:start_link({Ip, Port, Secret}),
    NewContacts = maps:put({Ip, Port}, #contact{pid = Pid}, Contacts),
    {Pid, NewContacts}.


kill_contact_workers(Contacts) ->
    maps:foreach(
        fun (_Addr, #contact{pid = Pid}) -> exit(Pid, normal) end,
        Contacts
    ),
    ok.

%% -----------------------------------------------------------------------------
