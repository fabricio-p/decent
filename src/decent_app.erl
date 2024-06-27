%%%-------------------------------------------------------------------
%% @doc decent public API
%% @end
%%%-------------------------------------------------------------------

-module(decent_app).

-behaviour(application).

-export([start/2, stop/1]).

start(_StartType, Nick) -> decent_sup:start_link(Nick).

stop(_State) -> ok.

%% internal functions
