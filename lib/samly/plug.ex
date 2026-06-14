defmodule Samly.Plug do
  @moduledoc """
  Endpoint-level plug for Samly SAML authentication.

  This is the canonical way to integrate Samly. Add it to your endpoint
  **after** body parsers and **before** your router — no Phoenix `forward`
  needed in your router at all:

      plug Plug.Parsers, ...
      plug Samly.Plug
      plug MyApp.Router

  ## What it handles

  For each configured identity provider, `Samly.Plug` intercepts:

  - **Legacy ACS/SLO paths** — requests whose path exactly matches the path
    component of `custom_consume_uri` or `custom_logout_uri`. This lets the
    app receive IdP callbacks at Shibboleth, Mellon, or any other registered
    URL without metadata re-registration.

  - **Standard Samly paths** — any request whose path starts with the path
    component of the IdP's `base_url` (e.g. `/sso/auth/signin/…`,
    `/sso/sp/metadata/…`). The `base_url` path is the base for the
    interactive SSO flow; set it to match where the IdP points users.

  Everything else passes through to the next plug unchanged.

  ## Configuration

  Set `base_url` to the base path you want Samly to occupy on this instance.
  For a standard deployment: `https://example.com/sso`. For a Shibboleth
  legacy deployment: `https://example.com/Shibboleth.sso`. For a Mellon
  legacy deployment: `https://example.com/mellon`.

  When redirecting unauthenticated users to the Samly sign-in flow, derive
  the path from `base_url`:

      base_path = URI.parse(System.get_env("SAML_IDP_BASE_URL")).path
      redirect_to = "\#{base_path}/auth/signin/\#{idp_id}?target_url=…"
  """

  @behaviour Plug
  import Plug.Conn

  def init(opts), do: opts

  def call(conn, _opts) do
    case find_route(conn) do
      nil ->
        conn

      routed_conn ->
        routed_conn
        |> Samly.Router.call([])
        |> halt()
    end
  end

  defp find_route(%{request_path: request_path} = conn) do
    Application.get_env(:samly, :identity_providers, %{})
    |> Enum.find_value(fn {_id, idp} ->
      cond do
        # Custom legacy paths take priority over base_url prefix matching so
        # that e.g. /mellon/postResponse isn't ambiguously matched as a
        # standard Samly path when base_url is also /mellon/….
        uri_path(idp.custom_consume_uri) == request_path ->
          %{conn | path_info: ["sp", "consume", idp.id]}

        uri_path(idp.custom_logout_uri) == request_path ->
          %{conn | path_info: ["sp", "logout", idp.id]}

        under_base_url?(request_path, idp.base_url) ->
          base = URI.parse(idp.base_url).path
          relative = String.slice(request_path, String.length(base)..-1//1)
          %{conn | path_info: split_path(relative)}

        true ->
          nil
      end
    end)
  end

  defp under_base_url?(_path, nil), do: false

  defp under_base_url?(request_path, base_url) do
    case URI.parse(base_url).path do
      nil -> false
      base -> String.starts_with?(request_path, base <> "/")
    end
  end

  @spec uri_path(nil | charlist()) :: nil | binary()
  defp uri_path(nil), do: nil

  defp uri_path(charlist) when is_list(charlist) do
    charlist |> List.to_string() |> URI.parse() |> Map.get(:path)
  end

  defp split_path(path), do: String.split(path, "/", trim: true)
end
