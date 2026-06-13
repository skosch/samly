defmodule Samly.State.StateUtil do
  @moduledoc false

  alias Samly.Assertion

  @spec validate_login_assertion_expiry(Assertion.t()) :: :valid | :expired
  def validate_login_assertion_expiry(%Assertion{subject: %{notonorafter: expiry_date}}) do
    if date_passed?(expiry_date), do: :expired, else: :valid
  end

  @spec validate_logout_assertion_expiry(Assertion.t()) :: :valid | :expired
  def validate_logout_assertion_expiry(%Assertion{authn: authn, subject: subject}) do
    # SessionNotOnOrAfter is the session lifetime constraint and governs SLO
    # eligibility when present. When the IdP omits it, fall back to the subject's
    # notonorafter (the assertion validity window): a session with no stated
    # lifetime is treated as expired once the assertion it was built from expires.
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
