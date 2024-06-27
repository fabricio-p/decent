%%%-------------------------------------------------------------------
%% @doc decent top level supervisor.
%% @end
%%%-------------------------------------------------------------------

-module(decent_sup).

-behaviour(supervisor).

-export([start_link/1]).
-export([init/1]).

-define(SERVER, ?MODULE).

start_link(Nick) -> supervisor:start_link({local, ?SERVER}, ?MODULE, Nick).

%% sup_flags() = #{strategy => strategy(),         % optional
%%                 intensity => non_neg_integer(), % optional
%%                 period => pos_integer()}        % optional
%% child_spec() = #{id => child_id(),       % mandatory
%%                  start => mfargs(),      % mandatory
%%                  restart => restart(),   % optional
%%                  shutdown => shutdown(), % optional
%%                  type => worker(),       % optional
%%                  modules => modules()}   % optional

init(Nick) ->
    SupFlags = #{strategy => one_for_one, intensity => 0, period => 1},
    ChildSpecs =
        [
            #{
                id => decent_server,
                start => {decent_server, start_link, [Nick]},
                restart => transient,
                shutdown => infinity,
                type => worker,
                modules => [decent_server]
            }
        ],
    {ok, {SupFlags, ChildSpecs}}.

%% internal functions
