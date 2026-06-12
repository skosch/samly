defmodule Samly.ConfigBehaviourTest do
  use Samly.RouterCase
  alias Samly.SPRouter

  def get_idp(_conn, idp_id) do
    assert idp_id == @idp_config.id
    Samly.IdpData.from_config(@sp_config, @idp_config)
  end

  setup do
    Application.put_env(:samly, :config_provider, Samly.ConfigBehaviourTest)
    setup_providers([], [])
  end

  test "GET on signin uri returns saml html form" do
    conn(:get, "/signin/idp1")
    |> init_test_session(%{})
    |> AuthRouter.call([])
    |> assert_initial_saml_form("%2F")
  end

  test "POST  consume saml assertion" do
    assertion =
      File.read!("./test/data/simplesaml_idp_assertion.xml")
      |> Base.encode64()

    conn =
      conn(:post, "/consume/idp1", %{
        SAMLResponse: assertion,
        RelayState: "OOhdIq-_PagPusisHCjYBZsYSwr-bVUs"
      })
      |> init_test_session(%{
        "relay_state" => "OOhdIq-_PagPusisHCjYBZsYSwr-bVUs",
        "idp_id" => "idp1",
        "target_url" => "/Home"
      })
      |> SPRouter.call([])

    assert conn.status == 302
    assert "/Home" = get_resp_header(conn, "location") |> List.first()
  end
end
