defmodule Samly.State.StateUtil do
  @moduledoc false

  alias Samly.Assertion

  @default_max_session_age 7 * 24 * 60 * 60

  @doc "Default cap (seconds) on a session whose IdP sent no SessionNotOnOrAfter."
  def default_max_session_age, do: @default_max_session_age

  @doc """
  Max session age (seconds) configured for the given IdP, or the default when
  the IdP is unknown. `nil` means no cap.
  """
  @spec max_session_age(String.t()) :: nil | pos_integer()
  def max_session_age(idp_id) do
    case Samly.Helper.get_idp(idp_id) do
      %Samly.IdpData{max_session_age: age} -> age
      _ -> @default_max_session_age
    end
  end

  @spec validate_login_assertion_expiry(Assertion.t(), nil | pos_integer()) :: :valid | :expired
  def validate_login_assertion_expiry(
        %Assertion{authn: authn} = assertion,
        max_session_age \\ @default_max_session_age
      ) do
    # Use SessionNotOnOrAfter when present — it is the actual SSO session lifetime.
    # The subject's NotOnOrAfter (SubjectConfirmationData) is a bearer-assertion
    # replay-protection window (5–15 min), not a session lifetime; gating ongoing
    # requests on it logs the user out minutes after login even though their SSO
    # session (and the IdP's) is still active.
    #
    # When the IdP sends no SessionNotOnOrAfter, fall back to a cap measured from
    # when this SP received the assertion (`received_at`, falling back to
    # `issue_instant`), so such sessions are not unlimited. If neither is
    # available the assertion is treated as expired.
    case Map.get(authn, "session_not_on_or_after") do
      nil -> within_max_age(assertion, max_session_age)
      session_exp -> if date_passed?(session_exp), do: :expired, else: :valid
    end
  end

  defp within_max_age(_assertion, nil), do: :valid

  defp within_max_age(assertion, max_age) do
    case session_start(assertion) do
      started_at when is_integer(started_at) ->
        if System.os_time(:second) - started_at < max_age, do: :valid, else: :expired

      _ ->
        :expired
    end
  end

  # When this SP received the assertion. Sessions stored before `received_at`
  # existed fall back to the assertion's IssueInstant (IdP clock, but within
  # seconds of receipt) so an upgrade does not log everyone out at once.
  # Unparsable or missing => nil => expired (fail closed).
  defp session_start(assertion) do
    case Map.get(assertion, :received_at) do
      received_at when is_integer(received_at) ->
        received_at

      _ ->
        case DateTime.from_iso8601(Map.get(assertion, :issue_instant) || "") do
          {:ok, issued, _} -> DateTime.to_unix(issued)
          _ -> nil
        end
    end
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
