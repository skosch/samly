defmodule Samly.ConfigBehaviour do
  @callback get_idp(conn :: Plug.Conn.t(), idp_id :: binary) :: nil | Samly.IdpData.t()
end
