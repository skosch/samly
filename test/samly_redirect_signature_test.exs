defmodule Samly.RedirectSignatureTest do
  use ExUnit.Case, async: true

  alias Samly.RedirectSignature

  @sig_alg "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"

  setup_all do
    [{:Certificate, der, _}] = "test/data/test.crt" |> File.read!() |> :public_key.pem_decode()
    [key_entry] = "test/data/test.pem" |> File.read!() |> :public_key.pem_decode()

    %{cert_b64: Base.encode64(der), key: :public_key.pem_entry_decode(key_entry)}
  end

  # Builds a redirect-binding query string signed over the canonical octets.
  defp signed_query(key, opts \\ []) do
    message_type = Keyword.get(opts, :message_type, "SAMLRequest")
    saml_value = Keyword.get(opts, :saml_value, "PHNhbWxwOkxvZ291dFJlcXVlc3QvPg==")
    relay_state = Keyword.get(opts, :relay_state, "rs-1234")
    sig_alg = Keyword.get(opts, :sig_alg, @sig_alg)

    encoded_msg = URI.encode_www_form(saml_value)

    parts =
      ["#{message_type}=#{encoded_msg}"] ++
        if(relay_state, do: ["RelayState=#{URI.encode_www_form(relay_state)}"], else: []) ++
        ["SigAlg=#{URI.encode_www_form(sig_alg)}"]

    signed = Enum.join(parts, "&")
    signature = :public_key.sign(signed, :sha256, key) |> Base.encode64() |> URI.encode_www_form()

    {signed, signed <> "&Signature=#{signature}"}
  end

  test "accepts a correctly signed redirect message", %{cert_b64: cert, key: key} do
    {_signed, query} = signed_query(key)
    assert :ok = RedirectSignature.verify(query, "SAMLRequest", [cert])
  end

  test "accepts a signed message with no RelayState", %{cert_b64: cert, key: key} do
    {_signed, query} = signed_query(key, relay_state: nil)
    assert :ok = RedirectSignature.verify(query, "SAMLRequest", [cert])
  end

  test "verifies against SAMLResponse messages too", %{cert_b64: cert, key: key} do
    {_signed, query} = signed_query(key, message_type: "SAMLResponse")
    assert :ok = RedirectSignature.verify(query, "SAMLResponse", [cert])
  end

  test "reports :no_signature when Signature/SigAlg are absent", %{cert_b64: cert} do
    query = "SAMLRequest=#{URI.encode_www_form("abc==")}&RelayState=rs"
    assert :no_signature = RedirectSignature.verify(query, "SAMLRequest", [cert])
  end

  test "rejects a tampered SAML message", %{cert_b64: cert, key: key} do
    {signed, query} = signed_query(key)
    # Flip the signed message but keep the original signature.
    tampered =
      String.replace(query, signed, String.replace(signed, "SAMLRequest=", "SAMLRequest=Zz"))

    assert {:error, :bad_redirect_signature} =
             RedirectSignature.verify(tampered, "SAMLRequest", [cert])
  end

  test "rejects a tampered RelayState", %{cert_b64: cert, key: key} do
    {_signed, query} = signed_query(key, relay_state: "original")
    tampered = String.replace(query, "RelayState=original", "RelayState=evil")

    assert {:error, :bad_redirect_signature} =
             RedirectSignature.verify(tampered, "SAMLRequest", [cert])
  end

  test "rejects when no trusted cert matches", %{key: key} do
    {_signed, query} = signed_query(key)
    other_cert = Base.encode64("not a real cert")

    assert {:error, :bad_redirect_signature} =
             RedirectSignature.verify(query, "SAMLRequest", [other_cert])
  end

  test "rejects when the cert list is empty", %{key: key} do
    {_signed, query} = signed_query(key)
    assert {:error, :bad_redirect_signature} = RedirectSignature.verify(query, "SAMLRequest", [])
  end

  test "rejects an unsupported signature algorithm", %{cert_b64: cert, key: key} do
    {_signed, query} = signed_query(key, sig_alg: "http://www.w3.org/2000/09/xmldsig#dsa-sha1")
    assert {:error, :unsupported_sig_alg} = RedirectSignature.verify(query, "SAMLRequest", [cert])
  end

  test "handles a non-binary query string defensively", %{cert_b64: cert} do
    assert :no_signature = RedirectSignature.verify(nil, "SAMLRequest", [cert])
  end
end
