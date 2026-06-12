defmodule Samly.ApplicationConfig do
  @behaviour Samly.ConfigBehaviour

  @impl true
  def get_idp(_conn, idp_id), do: Samly.Helper.get_idp(idp_id)
end
