defmodule Samly.RedirectSignature do
  @moduledoc false

  # HTTP-Redirect binding signature verification (SAML Bindings §3.4.4.1).
  #
  # For the Redirect binding the signature covers the percent-encoded query
  # string octets — `SAMLRequest|SAMLResponse`, optional `RelayState`, then
  # `SigAlg`, in that exact order — and is carried in the `Signature` query
  # parameter, NOT in the XML. esaml only knows how to verify XML (enveloped)
  # signatures, so a redirect-bound LogoutRequest/LogoutResponse cannot be
  # verified through esaml. This module fills that gap using the IdP's signing
  # certificate(s) from metadata.

  require Record
  require Logger

  Record.defrecordp(
    :certificate,
    :Certificate,
    Record.extract(:Certificate, from_lib: "public_key/include/public_key.hrl")
  )

  Record.defrecordp(
    :tbs_certificate,
    :TBSCertificate,
    Record.extract(:TBSCertificate, from_lib: "public_key/include/public_key.hrl")
  )

  Record.defrecordp(
    :subject_public_key_info,
    :SubjectPublicKeyInfo,
    Record.extract(:SubjectPublicKeyInfo, from_lib: "public_key/include/public_key.hrl")
  )

  @sig_algs %{
    "http://www.w3.org/2000/09/xmldsig#rsa-sha1" => :sha,
    "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256" => :sha256,
    "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384" => :sha384,
    "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512" => :sha512
  }

  @type message_type :: binary()
  @type result :: :ok | :no_signature | {:error, atom()}

  @doc """
  Verifies the redirect-binding signature carried in `query_string`.

  `message_type` is `"SAMLRequest"` or `"SAMLResponse"`. `certs` is the list of
  base64-encoded DER signing certificates from the IdP metadata.

  Returns `:no_signature` when the request carries no `Signature`/`SigAlg`, so the
  caller can decide whether an unsigned message is acceptable.
  """
  @spec verify(nil | binary(), message_type(), [binary()]) :: result()
  def verify(query_string, message_type, certs)
      when is_binary(query_string) and is_list(certs) do
    params = parse_raw_query(query_string)

    case {params["Signature"], params["SigAlg"]} do
      {nil, _} ->
        :no_signature

      {_, nil} ->
        :no_signature

      {sig_raw, sig_alg_raw} ->
        with {:ok, hash} <- hash_alg(url_decode(sig_alg_raw)),
             {:ok, signature} <- decode_signature(sig_raw),
             {:ok, signed} <- signed_octets(params, message_type) do
          if certs != [] and any_cert_verifies?(signed, hash, signature, certs) do
            :ok
          else
            {:error, :bad_redirect_signature}
          end
        end
    end
  end

  def verify(_query_string, _message_type, _certs), do: :no_signature

  # The signed octet string is the raw (still percent-encoded) parameter values
  # in the canonical order: message, then RelayState if present, then SigAlg.
  defp signed_octets(params, message_type) do
    case params[message_type] do
      nil ->
        {:error, :missing_saml_message}

      message_value ->
        parts =
          [{message_type, message_value}, relay_state_part(params), {"SigAlg", params["SigAlg"]}]
          |> Enum.reject(&is_nil/1)
          |> Enum.map(fn {k, v} -> "#{k}=#{v}" end)

        {:ok, Enum.join(parts, "&")}
    end
  end

  defp relay_state_part(%{"RelayState" => rs}) when is_binary(rs), do: {"RelayState", rs}
  defp relay_state_part(_), do: nil

  defp hash_alg(sig_alg_uri) do
    case Map.fetch(@sig_algs, sig_alg_uri) do
      {:ok, hash} -> {:ok, hash}
      :error -> {:error, :unsupported_sig_alg}
    end
  end

  defp decode_signature(sig_raw) do
    case sig_raw |> url_decode() |> Base.decode64() do
      {:ok, sig} -> {:ok, sig}
      :error -> {:error, :bad_redirect_signature}
    end
  end

  defp any_cert_verifies?(signed, hash, signature, certs) do
    Enum.any?(certs, fn cert ->
      case cert_public_key(cert) do
        {:ok, public_key} -> :public_key.verify(signed, hash, signature, public_key)
        :error -> false
      end
    end)
  end

  defp cert_public_key(cert_b64) do
    with {:ok, der} <- Base.decode64(cert_b64) do
      cert = :public_key.pkix_decode_cert(der, :plain)

      spki =
        cert
        |> certificate(:tbsCertificate)
        |> tbs_certificate(:subjectPublicKeyInfo)

      key_bin =
        case subject_public_key_info(spki, :subjectPublicKey) do
          {_, bin} -> bin
          bin -> bin
        end

      {:ok, :public_key.pem_entry_decode({:RSAPublicKey, key_bin, :not_encrypted})}
    else
      _ -> :error
    end
  rescue
    _ -> :error
  end

  defp parse_raw_query(query_string) do
    query_string
    |> String.split("&", trim: true)
    |> Enum.reduce(%{}, fn pair, acc ->
      case String.split(pair, "=", parts: 2) do
        [key, value] -> Map.put_new(acc, url_decode(key), value)
        [key] -> Map.put_new(acc, url_decode(key), "")
      end
    end)
  end

  defp url_decode(value) do
    URI.decode_www_form(value)
  rescue
    ArgumentError -> value
  end
end
