defmodule SamlyHelperTest do
  use ExUnit.Case
  require Samly.Esaml
  alias Samly.{Helper, IdpData, SpData}

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
    signed_envelopes_in_resp: false,
    force_authn: true
  }

  setup do
    sp_data = SpData.load_provider(@sp_config)
    sps = %{sp_data.id => sp_data}
    idp_data = IdpData.load_provider(@idp_config, sps)
    [idp_data: idp_data]
  end

  describe "gen_idp_signin_req with force_authn: true" do
    test "ForceAuthn attribute is present in generated XML", %{idp_data: idp_data} do
      assert idp_data.valid?
      assert idp_data.force_authn == true

      {_url, xml_frag} =
        Helper.gen_idp_signin_req(
          idp_data.esaml_sp_rec,
          idp_data.esaml_idp_rec,
          idp_data.nameid_format,
          true
        )

      # Export the XML fragment to a string and verify ForceAuthn is present
      exported = :xmerl.export_simple([xml_frag], :xmerl_xml) |> IO.iodata_to_binary()
      assert String.contains?(exported, "ForceAuthn")
    end

    test "ForceAuthn attribute is placed at index 8 (attributes field) of xmlElement", %{idp_data: idp_data} do
      {_url, xml_frag} =
        Helper.gen_idp_signin_req(
          idp_data.esaml_sp_rec,
          idp_data.esaml_idp_rec,
          idp_data.nameid_format,
          true
        )

      # xmlElement tuple: {:xmlElement, name, expanded_name, nsinfo, namespace, parents, pos, attributes, ...}
      # Index 8 is attributes (1-based, with tag atom at 1)
      assert is_tuple(xml_frag)
      assert elem(xml_frag, 0) == :xmlElement

      attributes = elem(xml_frag, 7)
      assert is_list(attributes)

      force_authn_attr =
        Enum.find(attributes, fn attr ->
          is_tuple(attr) and elem(attr, 0) == :xmlAttribute and elem(attr, 1) == :"ForceAuthn"
        end)

      assert force_authn_attr != nil, "ForceAuthn attribute not found at index 8 of xmlElement"
      assert elem(force_authn_attr, 8) == ~c"true"
    end

    test "ForceAuthn is NOT present when force_authn is false", %{idp_data: idp_data} do
      {_url, xml_frag} =
        Helper.gen_idp_signin_req(
          idp_data.esaml_sp_rec,
          idp_data.esaml_idp_rec,
          idp_data.nameid_format,
          false
        )

      exported = :xmerl.export_simple([xml_frag], :xmerl_xml) |> IO.iodata_to_binary()
      refute String.contains?(exported, "ForceAuthn")
    end
  end
end
