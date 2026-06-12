defmodule SamlyConfigTest do
  use ExUnit.Case

  alias Samly.Provider

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
    metadata_file: "test/data/idp_metadata.xml"
  }

  test "refresh_providers" do
    Application.put_env(:samly, Provider,
      service_providers: [@sp_config],
      identity_providers: [@idp_config]
    )

    assert Application.get_env(:samly, :service_providers) == nil
    assert Application.get_env(:samly, :identity_providers) == nil

    Provider.refresh_providers()

    sps = Application.get_env(:samly, :service_providers)
    assert sps == %{"sp1" => Samly.SpData.load_provider(@sp_config)}

    assert Application.get_env(:samly, :identity_providers) ==
             %{"idp1" => Samly.IdpData.load_provider(@idp_config, sps)}

    Application.delete_env(:samly, :service_providers)
    Application.delete_env(:samly, :identity_providers)
  end
end
