defmodule Samly.RouterCase do
  use ExUnit.CaseTemplate
  alias Samly.Provider

  using do
    quote do
      # Import conveniences for testing with connections
      use ExUnit.Case
      use Plug.Test

      import SweetXml

      alias Samly.AuthRouter

      import Samly.RouterCase

      @sp_config %{
        id: "sp1",
        entity_id: "urn:test:sp1",
        certfile: "test/data/test.crt",
        keyfile: "test/data/test.pem"
      }

      @idp_config %{
        id: "idp1",
        sp_id: "sp1",
        base_url: "http://samly.howto:4003/sso",
        metadata_file: "test/data/simplesaml_idp_metadata.xml",
        sign_requests: false,
        sign_metadata: false,
        signed_assertion_in_resp: false,
        signed_envelopes_in_resp: false
      }
    end
  end

  def setup_providers(sps, idps) do
    Application.put_env(:samly, Provider,
      service_providers: sps,
      identity_providers: idps
    )

    on_exit(fn ->
      Application.delete_env(:samly, :service_providers)
      Application.delete_env(:samly, :identity_providers)
      Application.delete_env(:samly, :config_provider)
    end)

    Provider.init([])
    :ok
  end

  def assert_form(conn, method, action) do
    assert conn.status == 200
    assert conn.method == method

    form = Floki.parse_document!(conn.resp_body) |> Floki.find("form")
    assert [^action] = Floki.attribute(form, "action")
    assert ["post"] = Floki.attribute(form, "method")

    form
  end

  def assert_initial_saml_form(conn, target_url) do
    assert [^target_url] =
             assert_form(conn, "GET", "/signin/idp1")
             |> Floki.attribute("input[name=target_url]", "value")
  end
end
