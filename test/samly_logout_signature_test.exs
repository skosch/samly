defmodule Samly.LogoutSignatureTest do
  @moduledoc """
  End-to-end coverage for HTTP-Redirect binding signature verification on
  incoming IdP LogoutRequests. The IdP metadata embeds the local test cert so we
  can sign requests with the matching test key and exercise the real handler.
  """
  use Samly.RouterCase

  alias Samly.{Assertion, State, Subject}
  alias Samly.SPRouter

  @nameid "_logout_user_nameid"
  @idp_entity_id "http://idp.test/metadata"

  setup do
    [{:Certificate, der, _}] = "test/data/test.crt" |> File.read!() |> :public_key.pem_decode()
    [key_entry] = "test/data/test.pem" |> File.read!() |> :public_key.pem_decode()
    cert_b64 = Base.encode64(der)
    key = :public_key.pem_entry_decode(key_entry)

    idp_config = %{
      id: "idp1",
      sp_id: "sp1",
      base_url: "http://samly.howto:4003/sso",
      metadata: idp_metadata(cert_b64),
      sign_requests: false,
      sign_metadata: false,
      signed_assertion_in_resp: false,
      signed_envelopes_in_resp: false,
      use_redirect_for_req: true,
      sign_logout_requests: true
    }

    setup_providers([@sp_config], [idp_config])

    # Seed a logged-in assertion so a successful logout has something to delete.
    seed_assertion()

    {:ok, key: key}
  end

  defp idp_metadata(cert_b64) do
    """
    <md:EntityDescriptor entityID="#{@idp_entity_id}"
      xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
      xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
      <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
        <md:KeyDescriptor use="signing">
          <ds:KeyInfo>
            <ds:X509Data><ds:X509Certificate>#{cert_b64}</ds:X509Certificate></ds:X509Data>
          </ds:KeyInfo>
        </md:KeyDescriptor>
        <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
          Location="http://idp.test/sso" />
        <md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
          Location="http://idp.test/slo" />
      </md:IDPSSODescriptor>
    </md:EntityDescriptor>
    """
  end

  defp seed_assertion do
    not_on_or_after = DateTime.utc_now() |> DateTime.add(8, :hour) |> DateTime.to_iso8601()

    assertion = %Assertion{
      idp_id: "idp1",
      subject: %Subject{name: @nameid, notonorafter: not_on_or_after},
      authn: %{}
    }

    State.put_assertion(Plug.Test.conn(:get, "/"), {"idp1", @nameid}, assertion)
  end

  defp logout_query(key, opts) do
    logout_request = """
    <samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
      xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
      ID="_lr#{System.unique_integer([:positive])}" Version="2.0"
      IssueInstant="2026-01-01T00:00:00Z">
      <saml:Issuer>#{@idp_entity_id}</saml:Issuer>
      <saml:NameID>#{@nameid}</saml:NameID>
    </samlp:LogoutRequest>
    """

    saml_request =
      logout_request |> :zlib.zip() |> Base.encode64() |> URI.encode_www_form()

    sig_alg = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
    signed = "SAMLRequest=#{saml_request}&SigAlg=#{URI.encode_www_form(sig_alg)}"

    if Keyword.get(opts, :sign, true) do
      signature =
        :public_key.sign(signed, :sha256, key) |> Base.encode64() |> URI.encode_www_form()

      signed <> "&Signature=#{signature}"
    else
      "SAMLRequest=#{saml_request}"
    end
  end

  defp call_logout(query) do
    conn(:get, "/logout/idp1?" <> query)
    |> init_test_session(%{})
    |> Plug.Conn.fetch_query_params()
    |> SPRouter.call([])
  end

  defp assertion_present? do
    State.get_assertion(Plug.Test.conn(:get, "/"), {"idp1", @nameid}) != nil
  end

  test "a validly signed logout request is processed and clears the session", %{key: key} do
    assert assertion_present?()

    conn = call_logout(logout_query(key, sign: true))

    # The handler responded to the IdP with a LogoutResponse...
    assert conn.status in [200, 302]
    # ...and the success path ran, deleting the stored assertion.
    refute assertion_present?()
  end

  test "an unsigned logout request is rejected and the session is preserved", %{key: key} do
    assert assertion_present?()

    conn = call_logout(logout_query(key, sign: false))

    assert conn.status in [200, 302]
    # The deny path short-circuited before touching the user's session.
    assert assertion_present?()
  end

  test "a logout request with a tampered signature is rejected", %{key: key} do
    query = logout_query(key, sign: true)
    tampered = String.replace(query, "SAMLRequest=", "SAMLRequest=Zz")

    conn = call_logout(tampered)

    assert conn.status in [200, 302]
    assert assertion_present?()
  end
end
