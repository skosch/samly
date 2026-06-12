defmodule Samly.State.StateUtil do
  @moduledoc false

  alias Samly.Assertion

  @spec validate_login_assertion_expiry(Assertion.t()) :: :valid | :expired
  def validate_login_assertion_expiry(%Assertion{subject: %{notonorafter: expiry_date}}) do
    if date_passed?(expiry_date), do: :expired, else: :valid
  end

  @spec validate_logout_assertion_expiry(Assertion.t()) :: :valid | :expired
  def validate_logout_assertion_expiry(%Assertion{authn: authn, subject: subject}) do
    # Use SessionNotOnOrAfter when present — it is a session lifetime constraint.
    # When absent, fall back to the subject's notonorafter (assertion validity window).
    # SessionNotOnOrAfter absent — allow SLO regardless of subject window
    expiry_date =
      case Map.get(authn, "session_not_on_or_after") do
        nil -> subject.notonorafter
        session_exp -> session_exp
      end

    if date_passed?(expiry_date), do: :expired, else: :valid
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
