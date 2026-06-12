defmodule Samly.AuthRouterTest do
  use Samly.RouterCase

  setup do
    setup_providers([@sp_config], [@idp_config])
  end

  test "GET on signin uri returns saml html form" do
    conn(:get, "/signin/idp1")
    |> init_test_session(%{})
    |> AuthRouter.call([])
    |> assert_initial_saml_form("%2F")
  end

  test "GET on signin uri returns saml html form with the given target url" do
    conn(:get, "/signin/idp1", target_url: "/Home")
    |> init_test_session(%{})
    |> AuthRouter.call([])
    |> assert_initial_saml_form("%2FHome")
  end

  test "POST on signin uri returns form that will be submited to idp" do
    assert ~c"urn:test:sp1" =
             conn(:post, "/signin/idp1", %{RelayState: "OOhdIq-_PagPusisHCjYBZsYSwr-bVUs"})
             |> put_private(:plug_skip_csrf_protection, true)
             |> put_private(:samly_nonce, "1mv+7BUs8o1nkOxa6ufS6kJ")
             |> init_test_session(%{})
             |> AuthRouter.call([])
             |> assert_form("POST", "http://samly.idp:8082/simplesaml/saml2/idp/SSOService.php")
             |> Floki.attribute("input[name=SAMLRequest]", "value")
             |> List.first()
             |> Base.decode64!()
             |> SweetXml.parse()
             |> SweetXml.xpath(~x"//saml:Issuer/text()")
  end
end
