defmodule Samly.ConfigBehaviourTest do
  use Samly.RouterCase
  alias Samly.SPRouter

  @req_id "id1727359569545809642114626"
  @consume_uri "http://samly.howto:4003/sso/sp/consume/idp1"
  @idp_entity_id "http://samly.idp:8082/simplesaml/saml2/idp/metadata.php"
  @relay_state "OOhdIq-_PagPusisHCjYBZsYSwr-bVUs"

  def get_idp(_conn, idp_id) do
    assert idp_id == @idp_config.id
    Samly.IdpData.from_config(@sp_config, @idp_config)
  end

  setup do
    Application.put_env(:samly, :config_provider, Samly.ConfigBehaviourTest)
    setup_providers([], [])
  end

  # Builds an unsigned SAML Response with a current validity window. Signatures
  # are disabled in the test IdP config, so esaml does not verify them. Each call
  # uses a unique Response ID so the replay cache treats them as distinct.
  defp saml_response(opts \\ []) do
    in_response_to = Keyword.get(opts, :in_response_to, @req_id)
    audience = Keyword.get(opts, :audience, "urn:test:sp1")
    destination = Keyword.get(opts, :destination, @consume_uri)

    now = DateTime.utc_now() |> DateTime.truncate(:second)
    iso = &(DateTime.add(now, &1, :second) |> DateTime.to_iso8601())
    not_before = iso.(-300)
    not_on_or_after = iso.(3600)
    session_expiry = iso.(8 * 3600)
    response_id = "_resp#{System.unique_integer([:positive])}"
    assertion_id = "_assert#{System.unique_integer([:positive])}"

    """
    <samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
      xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
      ID="#{response_id}" Version="2.0" IssueInstant="#{iso.(0)}"
      Destination="#{destination}" InResponseTo="#{in_response_to}">
      <saml:Issuer>#{@idp_entity_id}</saml:Issuer>
      <samlp:Status>
        <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success" />
      </samlp:Status>
      <saml:Assertion Version="2.0" ID="#{assertion_id}" IssueInstant="#{iso.(0)}">
        <saml:Issuer>#{@idp_entity_id}</saml:Issuer>
        <saml:Subject>
          <saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient"
            >_nameid_user1</saml:NameID>
          <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
            <saml:SubjectConfirmationData NotOnOrAfter="#{not_on_or_after}"
              Recipient="#{@consume_uri}" InResponseTo="#{in_response_to}" />
          </saml:SubjectConfirmation>
        </saml:Subject>
        <saml:Conditions NotBefore="#{not_before}" NotOnOrAfter="#{not_on_or_after}">
          <saml:AudienceRestriction>
            <saml:Audience>#{audience}</saml:Audience>
          </saml:AudienceRestriction>
        </saml:Conditions>
        <saml:AuthnStatement AuthnInstant="#{iso.(0)}" SessionNotOnOrAfter="#{session_expiry}"
          SessionIndex="_session1">
          <saml:AuthnContext>
            <saml:AuthnContextClassRef
              >urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef>
          </saml:AuthnContext>
        </saml:AuthnStatement>
        <saml:AttributeStatement>
          <saml:Attribute Name="email"
            NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
            <saml:AttributeValue>user1@example.com</saml:AttributeValue>
          </saml:Attribute>
        </saml:AttributeStatement>
      </saml:Assertion>
    </samlp:Response>
    """
    |> Base.encode64()
  end

  defp consume(saml_response, session) do
    conn(:post, "/consume/idp1", %{SAMLResponse: saml_response, RelayState: @relay_state})
    |> init_test_session(session)
    |> SPRouter.call([])
  end

  defp valid_session(overrides \\ %{}) do
    Map.merge(
      %{
        "relay_state" => @relay_state,
        "idp_id" => "idp1",
        "target_url" => "/Home",
        "req_id" => @req_id
      },
      overrides
    )
  end

  test "GET on signin uri returns saml html form" do
    conn(:get, "/signin/idp1")
    |> init_test_session(%{})
    |> AuthRouter.call([])
    |> assert_initial_saml_form("%2F")
  end

  test "POST consume saml assertion" do
    conn = consume(saml_response(), valid_session())

    assert conn.status == 302
    assert "/Home" = get_resp_header(conn, "location") |> List.first()
  end

  test "consume clears transient session keys after success" do
    conn = consume(saml_response(), valid_session())

    assert conn.status == 302
    assert Plug.Conn.get_session(conn, "relay_state") == nil
    assert Plug.Conn.get_session(conn, "req_id") == nil
    assert Plug.Conn.get_session(conn, "target_url") == nil
    assert Plug.Conn.get_session(conn, "samly_assertion_key") != nil
  end

  test "consume rejects a response whose InResponseTo does not match the stored request id" do
    conn = consume(saml_response(in_response_to: "id-attacker-chosen"), valid_session())
    assert conn.status == 403
  end

  test "consume rejects a response when no request id was stored (no AuthnRequest sent)" do
    session = valid_session() |> Map.delete("req_id")
    conn = consume(saml_response(), session)
    assert conn.status == 403
  end

  test "consume rejects a response addressed to the wrong audience" do
    conn = consume(saml_response(audience: "urn:some:other:sp"), valid_session())
    assert conn.status == 403
  end

  test "consume rejects a replayed response (same assertion twice)" do
    response = saml_response()

    conn1 = consume(response, valid_session())
    assert conn1.status == 302

    conn2 = consume(response, valid_session())
    assert conn2.status == 403
  end
end
