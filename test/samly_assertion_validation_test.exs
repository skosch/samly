defmodule Samly.AssertionValidationTest do
  use ExUnit.Case, async: true

  require Samly.Esaml

  alias Samly.{Assertion, AssertionValidation, Esaml, Subject}

  @recipient "http://samly.howto:4003/sso/sp/consume/idp1"
  @sp_entity_id "urn:test:sp1"
  @idp_entity_id "http://samly.idp:8082/simplesaml/saml2/idp/metadata.php"

  # ---------------------------------------------------------------------------
  # helpers
  # ---------------------------------------------------------------------------

  defp parse(xml) do
    {doc, _} = :xmerl_scan.string(String.to_charlist(xml), namespace_conformant: true)
    doc
  end

  defp response_xml(opts) do
    destination = Keyword.get(opts, :destination, @recipient)
    audiences = Keyword.get(opts, :audiences, [@sp_entity_id])
    not_before = Keyword.get(opts, :not_before, "2000-01-01T00:00:00Z")

    audience_xml =
      audiences
      |> Enum.map(fn a -> "<saml:Audience>#{a}</saml:Audience>" end)
      |> Enum.join()

    audience_restriction =
      case audiences do
        [] -> ""
        _ -> "<saml:AudienceRestriction>#{audience_xml}</saml:AudienceRestriction>"
      end

    destination_attr = if destination, do: ~s( Destination="#{destination}"), else: ""

    """
    <samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
      xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"#{destination_attr}>
      <saml:Issuer>#{@idp_entity_id}</saml:Issuer>
      <samlp:Status>
        <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success" />
      </samlp:Status>
      <saml:Assertion Version="2.0">
        <saml:Issuer>#{@idp_entity_id}</saml:Issuer>
        <saml:Conditions NotBefore="#{not_before}" NotOnOrAfter="2100-01-01T00:00:00Z">
          #{audience_restriction}
        </saml:Conditions>
      </saml:Assertion>
    </samlp:Response>
    """
  end

  defp sp_rec do
    Esaml.esaml_sp(
      consume_uri: String.to_charlist(@recipient),
      entity_id: String.to_charlist(@sp_entity_id)
    )
  end

  defp assertion(opts \\ []) do
    %Assertion{
      issuer: Keyword.get(opts, :issuer, @idp_entity_id),
      subject: %Subject{confirmation_method: Keyword.get(opts, :confirmation_method, :bearer)}
    }
  end

  # ---------------------------------------------------------------------------
  # check_issuer/2
  # ---------------------------------------------------------------------------

  describe "check_issuer/2" do
    test "accepts a matching issuer" do
      assert :ok = AssertionValidation.check_issuer(assertion(), @idp_entity_id)
    end

    test "rejects a mismatched issuer" do
      assert {:error, :issuer_mismatch} =
               AssertionValidation.check_issuer(assertion(), "https://evil.example.com")
    end

    test "skips the check when no expected issuer is configured" do
      assert :ok = AssertionValidation.check_issuer(assertion(issuer: "anything"), nil)
      assert :ok = AssertionValidation.check_issuer(assertion(issuer: "anything"), "")
    end
  end

  # ---------------------------------------------------------------------------
  # check_bearer/1
  # ---------------------------------------------------------------------------

  describe "check_bearer/1" do
    test "accepts bearer confirmation" do
      assert :ok = AssertionValidation.check_bearer(assertion(confirmation_method: :bearer))
    end

    test "rejects non-bearer confirmation" do
      assert {:error, :non_bearer_confirmation} =
               AssertionValidation.check_bearer(assertion(confirmation_method: :unknown))
    end
  end

  # ---------------------------------------------------------------------------
  # check_destination/2
  # ---------------------------------------------------------------------------

  describe "check_destination/2" do
    test "accepts a matching Destination" do
      xml = parse(response_xml(destination: @recipient))
      assert :ok = AssertionValidation.check_destination(xml, @recipient)
    end

    test "rejects a mismatched Destination" do
      xml = parse(response_xml(destination: "http://evil.example.com/consume"))
      assert {:error, :bad_destination} = AssertionValidation.check_destination(xml, @recipient)
    end

    test "accepts when Destination is absent (optional attribute)" do
      xml = parse(response_xml(destination: nil))
      assert :ok = AssertionValidation.check_destination(xml, @recipient)
    end

    test "skips the check when recipient is unknown" do
      xml = parse(response_xml(destination: "http://anything"))
      assert :ok = AssertionValidation.check_destination(xml, nil)
    end
  end

  # ---------------------------------------------------------------------------
  # check_audience/2
  # ---------------------------------------------------------------------------

  describe "check_audience/2" do
    test "accepts when the SP is the only audience" do
      xml = parse(response_xml(audiences: [@sp_entity_id]))
      assert :ok = AssertionValidation.check_audience(xml, @sp_entity_id)
    end

    test "accepts when the SP is among multiple audiences" do
      xml = parse(response_xml(audiences: ["urn:other:sp", @sp_entity_id]))
      assert :ok = AssertionValidation.check_audience(xml, @sp_entity_id)
    end

    test "rejects a multi-audience assertion that omits the SP (the esaml bypass)" do
      xml = parse(response_xml(audiences: ["urn:other:sp", "urn:another:sp"]))
      assert {:error, :bad_audience} = AssertionValidation.check_audience(xml, @sp_entity_id)
    end

    test "accepts when no AudienceRestriction is present" do
      xml = parse(response_xml(audiences: []))
      assert :ok = AssertionValidation.check_audience(xml, @sp_entity_id)
    end

    test "skips the check when the SP entity id is unknown" do
      xml = parse(response_xml(audiences: ["urn:other:sp"]))
      assert :ok = AssertionValidation.check_audience(xml, nil)
    end
  end

  # ---------------------------------------------------------------------------
  # check_notbefore/3
  # ---------------------------------------------------------------------------

  describe "check_notbefore/3" do
    @now ~U[2026-06-12 12:00:00Z]

    test "accepts an assertion whose NotBefore has passed" do
      xml = parse(response_xml(not_before: "2026-06-12T11:00:00Z"))
      assert :ok = AssertionValidation.check_notbefore(xml, 90, @now)
    end

    test "rejects an assertion that is not yet valid" do
      xml = parse(response_xml(not_before: "2026-06-12T13:00:00Z"))

      assert {:error, :assertion_not_yet_valid} =
               AssertionValidation.check_notbefore(xml, 90, @now)
    end

    test "tolerates clock skew at the boundary" do
      # NotBefore is 60s in the future; a 90s skew allowance accepts it.
      xml = parse(response_xml(not_before: "2026-06-12T12:01:00Z"))
      assert :ok = AssertionValidation.check_notbefore(xml, 90, @now)

      # ...but a 30s allowance does not.
      assert {:error, :assertion_not_yet_valid} =
               AssertionValidation.check_notbefore(xml, 30, @now)
    end

    test "accepts when NotBefore is absent" do
      no_nb = """
      <samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
        xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
        <saml:Assertion Version="2.0">
          <saml:Conditions NotOnOrAfter="2100-01-01T00:00:00Z" />
        </saml:Assertion>
      </samlp:Response>
      """

      assert :ok = AssertionValidation.check_notbefore(parse(no_nb), 90, @now)
    end

    test "rejects an unparseable NotBefore" do
      xml = parse(response_xml(not_before: "not-a-date"))
      assert {:error, :invalid_notbefore} = AssertionValidation.check_notbefore(xml, 90, @now)
    end
  end

  # ---------------------------------------------------------------------------
  # validate/4 (end-to-end over a full response)
  # ---------------------------------------------------------------------------

  describe "validate/4" do
    test "accepts a well-formed response" do
      xml = parse(response_xml([]))
      assert :ok = AssertionValidation.validate(xml, assertion(), sp_rec(), @idp_entity_id)
    end

    test "rejects on issuer mismatch" do
      xml = parse(response_xml([]))

      assert {:error, :issuer_mismatch} =
               AssertionValidation.validate(xml, assertion(), sp_rec(), "urn:wrong:idp")
    end

    test "rejects on audience bypass" do
      xml = parse(response_xml(audiences: ["urn:other:sp", "urn:another:sp"]))

      assert {:error, :bad_audience} =
               AssertionValidation.validate(xml, assertion(), sp_rec(), @idp_entity_id)
    end

    test "rejects on non-bearer confirmation" do
      xml = parse(response_xml([]))

      assert {:error, :non_bearer_confirmation} =
               AssertionValidation.validate(
                 xml,
                 assertion(confirmation_method: :unknown),
                 sp_rec(),
                 @idp_entity_id
               )
    end
  end
end
