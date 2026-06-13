defmodule Samly.State.StateUtil do
  @moduledoc false

  alias Samly.Assertion

  @spec validate_login_assertion_expiry(Assertion.t()) :: :valid | :expired
  def validate_login_assertion_expiry(%Assertion{subject: %{notonorafter: expiry_date}}) do
    if date_passed?(expiry_date), do: :expired, else: :valid
  end

  @spec validate_logout_assertion_expiry(Assertion.t()) :: :valid | :expired
  def validate_logout_assertion_expiry(%Assertion{authn: authn}) do
    # Use SessionNotOnOrAfter when present — it is the actual SSO session lifetime.
    # When absent (the common case), allow SLO regardless: the subject's NotOnOrAfter
    # is an assertion replay-protection window (5–15 min), not a session lifetime, and
    # must not prevent a user from logging out of an active session.
    case Map.get(authn, "session_not_on_or_after") do
      nil -> :valid
      session_exp -> if date_passed?(session_exp), do: :expired, else: :valid
    end
  end

  defp date_passed?(expiry_date) do
    now = DateTime.utc_now()

    case DateTime.from_iso8601(expiry_date) do
      {:ok, expiry_date, _} ->
        if DateTime.compare(now, expiry_date) == :lt, do: false, else: true

      _ ->
        true
    end
  end
end
