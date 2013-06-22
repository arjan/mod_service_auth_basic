%% @author Arjan Scherpenisse
%% @copyright 2013 Arjan Scherpenisse

%% @doc Provides basic authentication for Zotonic API calls. Plug this
%% module in and your API calls will be accessible using the
%% "Authorization: Basic <base64>" request header. Note that this
%% authentication method can only be trusted over a HTTPS connection,
%% as the username and password are transfered over the wire.

-module(mod_service_auth_basic).
-author("Arjan Scherpenisse").

-mod_title("Basic API service authentication").
-mod_description("Provides basic authentication for Zotonic API calls.").
-mod_prio(500).

-include_lib("zotonic.hrl").

-export([
         observe_service_authorize/2
        ]).


%%====================================================================
%% API
%%====================================================================

observe_service_authorize(#service_authorize{}, Context) ->
    ReqData = z_context:get_reqdata(Context),
    case z_context:get_req_header("authorization", Context) of
        "Basic " ++ Base64 ->
            [User, Pass] = string:tokens(binary_to_list(base64:decode(Base64)), ":"),
            case m_identity:check_username_pw(User, Pass, Context) of
                {ok, UserId} ->
                    AuthContext = z_acl:logon(UserId, Context),
                    {true, ReqData, AuthContext};
                {error, _} ->
                    authorize("Username/password combination incorrect.", Context)
            end;
        _ ->
            authorize("Authorization required.", Context)
    end.


authorize(Reason, Context) ->
    ReqData = z_context:get_reqdata(Context),
    ReqData1 = wrq:set_resp_body(Reason ++ "\n", ReqData),
    {{halt, 401}, ReqData1, Context}.
