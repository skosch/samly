defmodule Samly.RouterUtil do
  @moduledoc false

  alias Plug.Conn
  require Logger
  require Samly.Esaml
  alias Samly.{Esaml, IdpData, Helper}

  @subdomain_re ~r/^(?<subdomain>([^.]+))?\./

  def check_idp_id(%Conn{private: %{samly_idp: %IdpData{valid?: true}}} = conn, _opts), do: conn

  def check_idp_id(conn, _opts) do
    idp_id_from = Application.get_env(:samly, :idp_id_from)

    idp_id =
      if idp_id_from == :subdomain do
        case Regex.named_captures(@subdomain_re, conn.host) do
          %{"subdomain" => idp_id} -> idp_id
          _ -> nil
        end
      else
        case conn.params["idp_id_seg"] do
          [idp_id] -> idp_id
          _ -> nil
        end
      end

    config = Application.get_env(:samly, :config_provider, Samly.ApplicationConfig)

    idp = idp_id && config.get_idp(conn, idp_id)

    idp =
      case idp do
        %IdpData{valid?: false} -> nil
        other -> other
      end

    if idp do
      conn |> Conn.put_private(:samly_idp, idp)
    else
      Logger.error("[Samly] check_idp_id: unknown or invalid IdP #{inspect(idp_id)} (loaded: #{inspect(Map.keys(Application.get_env(:samly, :identity_providers, %{})))})")
      Helper.handle_error_response(conn, :unknown_idp, 403, "invalid_request unknown IdP")
    end
  end

  def check_target_url(conn, _opts) do
    try do
      target_url = conn.params["target_url"] && URI.decode_www_form(conn.params["target_url"])

      if relative_target_url?(target_url) do
        conn |> Conn.put_private(:samly_target_url, target_url)
      else
        Logger.error("[Samly] rejected non-relative target_url: #{inspect(target_url)}")

        Helper.handle_error_response(
          conn,
          :invalid_target_url,
          400,
          "target_url must be a relative path"
        )
      end
    rescue
      ArgumentError ->
        Logger.error(
          "[Samly] target_url must be x-www-form-urlencoded: #{inspect(conn.params["target_url"])}"
        )

        Helper.handle_error_response(
          conn,
          :invalid_target_url_encoding,
          400,
          "target_url must be x-www-form-urlencoded"
        )
    end
  end

  # A redirect target controlled by request parameters must stay on this site, or
  # it becomes an open redirect. Accept only site-relative paths by default;
  # protocol-relative ("//host") and absolute ("https://host") URLs are rejected.
  # Set `config :samly, allow_absolute_target_urls: true` to opt out.
  @spec relative_target_url?(nil | binary) :: boolean
  def relative_target_url?(url) when url in [nil, ""], do: true

  def relative_target_url?(url) when is_binary(url) do
    cond do
      Application.get_env(:samly, :allow_absolute_target_urls, false) -> true
      String.starts_with?(url, "//") -> false
      String.starts_with?(url, "/") -> true
      true -> false
    end
  end

  # generate URIs using the idp_id
  @spec ensure_sp_uris_set(tuple, Conn.t()) :: tuple
  def ensure_sp_uris_set(sp, conn) do
    case Esaml.esaml_sp(sp, :metadata_uri) do
      [?/ | _] ->
        uri = %URI{
          scheme: Atom.to_string(conn.scheme),
          host: conn.host,
          port: conn.port,
          path: "/sso"
        }

        base_url = URI.to_string(uri)
        idp_id_from = Application.get_env(:samly, :idp_id_from)
        %IdpData{id: idp_id} = idp_data = conn.private[:samly_idp]

        path_segment_idp_id =
          if idp_id_from == :subdomain do
            nil
          else
            idp_id
          end

        Esaml.esaml_sp(
          sp,
          metadata_uri: Helper.get_metadata_uri(base_url, path_segment_idp_id),
          consume_uri:
            idp_data.custom_consume_uri || Helper.get_consume_uri(base_url, path_segment_idp_id),
          logout_uri:
            idp_data.custom_logout_uri || Helper.get_logout_uri(base_url, path_segment_idp_id)
        )

      _ ->
        sp
    end
  end

  def send_saml_request(conn, idp_url, use_redirect?, signed_xml_payload, relay_state) do
    if use_redirect? do
      url =
        :esaml_binding.encode_http_redirect(idp_url, signed_xml_payload, :undefined, relay_state)

      conn |> redirect(302, url)
    else
      nonce = conn.private[:samly_nonce]
      resp_body = :esaml_binding.encode_http_post(idp_url, signed_xml_payload, relay_state, nonce)

      conn
      |> Conn.put_resp_header("content-type", "text/html")
      |> Conn.send_resp(200, resp_body)
    end
  end

  def redirect(conn, status_code, dest) do
    conn
    |> Conn.put_resp_header("location", dest)
    |> Conn.send_resp(status_code, "")
    |> Conn.halt()
  end
end
