defmodule Samly.PlugTest do
  use ExUnit.Case
  use Plug.Test

  alias Samly.Provider

  @sp_config %{
    id: "sp1",
    entity_id: "urn:test:sp1",
    certfile: "test/data/test.crt",
    keyfile: "test/data/test.pem"
  }

  # Standard deployment: Samly lives at /sso
  @idp_config_sso %{
    id: "idp1",
    sp_id: "sp1",
    base_url: "http://samly.howto:4003/sso",
    metadata_file: "test/data/simplesaml_idp_metadata.xml",
    sign_requests: false,
    sign_metadata: false,
    signed_assertion_in_resp: false,
    signed_envelopes_in_resp: false
  }

  # Legacy Mellon deployment: base_url uses /mellon, ACS/SLO at non-standard paths
  @idp_config_mellon %{
    id: "idp1",
    sp_id: "sp1",
    base_url: "http://example.com/mellon",
    metadata_file: "test/data/simplesaml_idp_metadata.xml",
    sign_requests: false,
    sign_metadata: false,
    signed_assertion_in_resp: false,
    signed_envelopes_in_resp: false,
    custom_consume_uri: "http://example.com/mellon/postResponse",
    custom_logout_uri: "http://example.com/mellon/logout"
  }

  setup do
    on_exit(fn ->
      Application.delete_env(:samly, :service_providers)
      Application.delete_env(:samly, :identity_providers)
      Application.delete_env(:samly, :config_provider)
    end)
  end

  defp setup_providers(sps, idps) do
    Application.put_env(:samly, Provider,
      service_providers: sps,
      identity_providers: idps
    )

    Provider.init([])
  end

  describe "pass-through behaviour" do
    setup do
      setup_providers([@sp_config], [@idp_config_sso])
    end

    test "unrelated path is not halted" do
      conn = conn(:get, "/admin/dashboard") |> Samly.Plug.call([])
      refute conn.halted
    end

    test "path with a different prefix is not halted" do
      conn = conn(:get, "/other/auth/signin/idp1") |> Samly.Plug.call([])
      refute conn.halted
    end

    test "path exactly equal to base_url (no trailing slash) is not halted" do
      # /sso on its own is not a Samly route; only /sso/… is
      conn = conn(:get, "/sso") |> Samly.Plug.call([])
      refute conn.halted
    end
  end

  describe "standard /sso base_url routing" do
    setup do
      setup_providers([@sp_config], [@idp_config_sso])
    end

    test "GET /sso/auth/signin/:idp is intercepted and returns 200" do
      conn =
        conn(:get, "/sso/auth/signin/idp1")
        |> init_test_session(%{})
        |> Samly.Plug.call([])

      assert conn.halted
      assert conn.status == 200
    end

    test "GET /sso/sp/metadata/:idp is intercepted" do
      conn =
        conn(:get, "/sso/sp/metadata/idp1")
        |> init_test_session(%{})
        |> Samly.Plug.call([])

      assert conn.halted
    end
  end

  describe "legacy /mellon base_url routing" do
    setup do
      setup_providers([@sp_config], [@idp_config_mellon])
    end

    test "GET /mellon/auth/signin/:idp is intercepted and returns 200" do
      conn =
        conn(:get, "/mellon/auth/signin/idp1")
        |> init_test_session(%{})
        |> Samly.Plug.call([])

      assert conn.halted
      assert conn.status == 200
    end

    test "unrelated path is not intercepted even when base_url is /mellon" do
      conn = conn(:get, "/admin/dashboard") |> Samly.Plug.call([])
      refute conn.halted
    end
  end

  describe "custom ACS/SLO path routing" do
    setup do
      setup_providers([@sp_config], [@idp_config_mellon])
    end

    test "POST to custom_consume_uri is intercepted" do
      # No valid SAML body — Samly will return an error — but the plug must
      # have routed it (conn halted). In production Plug.Parsers runs first;
      # here we pre-populate body_params so SPHandler doesn't crash on the
      # unfetched sentinel.
      conn =
        conn(:post, "/mellon/postResponse")
        |> Map.put(:body_params, %{})
        |> put_private(:plug_skip_csrf_protection, true)
        |> init_test_session(%{})
        |> Samly.Plug.call([])

      assert conn.halted
    end

    test "GET to custom_logout_uri is intercepted" do
      conn =
        conn(:get, "/mellon/logout")
        |> init_test_session(%{})
        |> Samly.Plug.call([])

      assert conn.halted
    end

    test "custom_consume_uri takes priority over base_url prefix for ambiguous paths" do
      # /mellon/postResponse matches both the base_url prefix (/mellon/…) and
      # the exact custom_consume_uri path. The consume handler must win so that
      # path_info is ["sp", "consume", idp_id] rather than ["postResponse"].
      # A 404 would mean the base_url branch matched and produced path_info
      # ["postResponse"], which has no route in Samly.Router.
      conn =
        conn(:post, "/mellon/postResponse")
        |> Map.put(:body_params, %{})
        |> put_private(:plug_skip_csrf_protection, true)
        |> init_test_session(%{})
        |> Samly.Plug.call([])

      assert conn.halted
      refute conn.status == 404
    end
  end
end
