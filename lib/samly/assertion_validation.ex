defmodule Samly.AssertionValidation do
  @moduledoc false

  # SP-side SAML 2.0 conformance checks that complement esaml's signature,
  # recipient and staleness validation. These cover requirements esaml does not
  # fully enforce:
  #
  #   * Issuer matches the configured IdP entityID (Core §3.2.1). esaml pins the
  #     signing cert by fingerprint, but two IdPs sharing a cert would otherwise
  #     be interchangeable.
  #   * Destination matches the ACS URL on signed POST messages (Bindings §3.5.5.2).
  #   * The SP is among the assertion's audiences (Core §2.5.1.4). esaml silently
  #     drops the audience condition when more than one <Audience> is present, so
  #     a multi-audience assertion would otherwise bypass the check entirely.
  #   * Conditions/@NotBefore has passed, within a configurable clock skew
  #     (Core §2.5.1.2).
  #   * SubjectConfirmation is bearer (Web SSO profile §4.1.4.2).
  #
  # All functions are pure given the response XML / assertion and are unit
  # tested in test/samly_assertion_validation_test.exs.

  require Record
  require Samly.Esaml

  alias Samly.{Assertion, Esaml, Subject}

  Record.defrecordp(
    :xml_attribute,
    :xmlAttribute,
    Record.extract(:xmlAttribute, from_lib: "xmerl/include/xmerl.hrl")
  )

  Record.defrecordp(
    :xml_text,
    :xmlText,
    Record.extract(:xmlText, from_lib: "xmerl/include/xmerl.hrl")
  )

  @ns [
    {~c"samlp", ~c"urn:oasis:names:tc:SAML:2.0:protocol"},
    {~c"saml", ~c"urn:oasis:names:tc:SAML:2.0:assertion"}
  ]

  @default_clock_skew_secs 90

  @type reason ::
          :issuer_mismatch
          | :bad_destination
          | :bad_audience
          | :assertion_not_yet_valid
          | :invalid_notbefore
          | :non_bearer_confirmation

  @doc """
  Runs all compensating checks over a decoded SAML response.

  `response_xml` is the xmerl-parsed `samlp:Response` element, `assertion` is the
  decoded `Samly.Assertion`, `sp` is the esaml SP record and `expected_issuer` is
  the configured IdP entityID (or `nil` to skip the issuer check).
  """
  @spec validate(tuple(), Assertion.t(), tuple(), nil | binary()) :: :ok | {:error, reason()}
  def validate(response_xml, %Assertion{} = assertion, sp, expected_issuer) do
    recipient = sp |> Esaml.esaml_sp(:consume_uri) |> charlist_to_string()
    sp_entity_id = sp |> Esaml.esaml_sp(:entity_id) |> charlist_to_string()

    with :ok <- check_issuer(assertion, expected_issuer),
         :ok <- check_bearer(assertion),
         :ok <- check_destination(response_xml, recipient),
         :ok <- check_audience(response_xml, sp_entity_id),
         :ok <- check_notbefore(response_xml, clock_skew_secs(), DateTime.utc_now()) do
      :ok
    end
  end

  @spec check_issuer(Assertion.t(), nil | binary()) :: :ok | {:error, :issuer_mismatch}
  def check_issuer(_assertion, nil), do: :ok
  def check_issuer(_assertion, ""), do: :ok

  def check_issuer(%Assertion{issuer: issuer}, expected) do
    if issuer == expected, do: :ok, else: {:error, :issuer_mismatch}
  end

  @spec check_bearer(Assertion.t()) :: :ok | {:error, :non_bearer_confirmation}
  def check_bearer(%Assertion{subject: %Subject{confirmation_method: :bearer}}), do: :ok
  def check_bearer(%Assertion{}), do: {:error, :non_bearer_confirmation}

  @spec check_destination(tuple(), nil | binary()) :: :ok | {:error, :bad_destination}
  def check_destination(_response_xml, nil), do: :ok

  def check_destination(response_xml, recipient) do
    # Destination is optional; esaml already enforces the SubjectConfirmationData
    # Recipient. When Destination is present on a signed message it must match.
    case attr_value(response_xml, ~c"/samlp:Response/@Destination") do
      empty when empty in [nil, ""] -> :ok
      ^recipient -> :ok
      _ -> {:error, :bad_destination}
    end
  end

  @spec check_audience(tuple(), nil | binary()) :: :ok | {:error, :bad_audience}
  def check_audience(_response_xml, empty) when empty in [nil, ""], do: :ok

  def check_audience(response_xml, sp_entity_id) do
    case audiences(response_xml) do
      [] -> :ok
      audiences -> if sp_entity_id in audiences, do: :ok, else: {:error, :bad_audience}
    end
  end

  @spec check_notbefore(tuple(), non_neg_integer(), DateTime.t()) ::
          :ok | {:error, :assertion_not_yet_valid | :invalid_notbefore}
  def check_notbefore(response_xml, skew_secs, now) do
    case attr_value(response_xml, ~c"/samlp:Response/saml:Assertion/saml:Conditions/@NotBefore") do
      empty when empty in [nil, ""] ->
        :ok

      not_before ->
        case DateTime.from_iso8601(not_before) do
          {:ok, not_before_dt, _} ->
            threshold = DateTime.add(now, skew_secs, :second)

            if DateTime.compare(threshold, not_before_dt) == :lt,
              do: {:error, :assertion_not_yet_valid},
              else: :ok

          _ ->
            {:error, :invalid_notbefore}
        end
    end
  end

  defp audiences(response_xml) do
    response_xml
    |> xpath_all(
      ~c"/samlp:Response/saml:Assertion/saml:Conditions/saml:AudienceRestriction/saml:Audience/text()"
    )
    |> Enum.map(fn node -> node |> xml_text(:value) |> List.to_string() |> String.trim() end)
    |> Enum.reject(&(&1 == ""))
  end

  defp attr_value(xml, path) do
    case :xmerl_xpath.string(path, xml, [{:namespace, @ns}]) do
      [attr | _] -> attr |> xml_attribute(:value) |> List.to_string()
      _ -> nil
    end
  end

  defp xpath_all(xml, path), do: :xmerl_xpath.string(path, xml, [{:namespace, @ns}])

  defp charlist_to_string(:undefined), do: nil
  defp charlist_to_string([]), do: nil
  defp charlist_to_string(s) when is_list(s), do: List.to_string(s)
  defp charlist_to_string(s) when is_binary(s), do: s

  defp clock_skew_secs do
    case Application.get_env(:samly, :clock_skew_secs, @default_clock_skew_secs) do
      n when is_integer(n) and n >= 0 -> n
      _ -> @default_clock_skew_secs
    end
  end
end
