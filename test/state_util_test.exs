defmodule Samly.StateUtilTest do
  @moduledoc false

  use ExUnit.Case, async: true

  alias Samly.State.StateUtil

  describe "validate_login_assertion_expiry/1" do
    test "is :expired when the SSO session (session_not_on_or_after) has ended" do
      # Arrange
      not_on_or_after = DateTime.utc_now() |> DateTime.add(8, :hour) |> DateTime.to_iso8601()

      session_not_on_or_after =
        DateTime.utc_now() |> DateTime.add(-8, :hour) |> DateTime.to_iso8601()

      assertion = %Samly.Assertion{
        subject: %{notonorafter: not_on_or_after},
        authn: %{"session_not_on_or_after" => session_not_on_or_after}
      }

      # Act
      result = StateUtil.validate_login_assertion_expiry(assertion)

      # Assert
      assert result == :expired
    end

    test "is :valid when assertion has not expired for" do
      # Arrange
      not_on_or_after = DateTime.utc_now() |> DateTime.add(8, :hour) |> DateTime.to_iso8601()

      session_not_on_or_after =
        DateTime.utc_now() |> DateTime.add(8, :hour) |> DateTime.to_iso8601()

      assertion = %Samly.Assertion{
        subject: %{notonorafter: not_on_or_after},
        authn: %{"session_not_on_or_after" => session_not_on_or_after}
      }

      # Act
      result = StateUtil.validate_login_assertion_expiry(assertion)

      # Assert
      assert result == :valid
    end
  end

  describe "validate_login_assertion_expiry: subject replay window" do
    test "is :valid when only the subject NotOnOrAfter has passed but the session is active" do
      # Regression: gating on subject.notonorafter logged users out minutes after login.
      past = DateTime.utc_now() |> DateTime.add(-8, :hour) |> DateTime.to_iso8601()
      future = DateTime.utc_now() |> DateTime.add(8, :hour) |> DateTime.to_iso8601()

      assertion = %Samly.Assertion{
        subject: %{notonorafter: past},
        authn: %{"session_not_on_or_after" => future}
      }

      assert StateUtil.validate_login_assertion_expiry(assertion) == :valid
    end
  end

  describe "validate_login_assertion_expiry: max session age (no session_not_on_or_after)" do
    defp received(seconds_ago),
      do: %Samly.Assertion{authn: %{}, received_at: System.os_time(:second) - seconds_ago}

    test "default cap is 7 days" do
      assert StateUtil.default_max_session_age() == 7 * 24 * 60 * 60
    end

    test "is :valid within the default cap" do
      assert StateUtil.validate_login_assertion_expiry(received(6 * 24 * 3600)) == :valid
    end

    test "is :expired beyond the default cap" do
      assert StateUtil.validate_login_assertion_expiry(received(8 * 24 * 3600)) == :expired
    end

    test "honours an explicit cap" do
      assert StateUtil.validate_login_assertion_expiry(received(120), 60) == :expired
      assert StateUtil.validate_login_assertion_expiry(received(30), 60) == :valid
    end

    test "nil cap disables the limit" do
      assert StateUtil.validate_login_assertion_expiry(received(10 * 365 * 24 * 3600), nil) ==
               :valid
    end

    test "assertion without received_at is :expired (fail closed)" do
      assert StateUtil.validate_login_assertion_expiry(%Samly.Assertion{authn: %{}}) == :expired
    end

    test "the cap is ignored when the IdP sent session_not_on_or_after" do
      future = DateTime.utc_now() |> DateTime.add(30, :day) |> DateTime.to_iso8601()

      assertion = %Samly.Assertion{
        authn: %{"session_not_on_or_after" => future},
        received_at: System.os_time(:second) - 30 * 24 * 3600
      }

      assert StateUtil.validate_login_assertion_expiry(assertion, 3600) == :valid
    end

    test "max_session_age/1 falls back to the default for an unknown IdP" do
      assert StateUtil.max_session_age("no-such-idp") == StateUtil.default_max_session_age()
    end
  end

  describe "validate_logout_assertion_expiry/1" do
    test "is :expired when assertion is expired" do
      # Arrange
      not_on_or_after = DateTime.utc_now() |> DateTime.add(8, :hour) |> DateTime.to_iso8601()

      session_not_on_or_after =
        DateTime.utc_now() |> DateTime.add(-8, :hour) |> DateTime.to_iso8601()

      assertion = %Samly.Assertion{
        subject: %{notonorafter: not_on_or_after},
        authn: %{"session_not_on_or_after" => session_not_on_or_after}
      }

      # Act
      result = StateUtil.validate_logout_assertion_expiry(assertion)

      # Assert
      assert result == :expired
    end

    test "is :valid when assertion has not expired" do
      # Arrange
      not_on_or_after = DateTime.utc_now() |> DateTime.add(-8, :hour) |> DateTime.to_iso8601()

      session_not_on_or_after =
        DateTime.utc_now() |> DateTime.add(8, :hour) |> DateTime.to_iso8601()

      assertion = %Samly.Assertion{
        subject: %{notonorafter: not_on_or_after},
        authn: %{"session_not_on_or_after" => session_not_on_or_after}
      }

      # Act
      result = StateUtil.validate_logout_assertion_expiry(assertion)

      # Assert
      assert result == :valid
    end

    test "is :valid when session_not_on_or_after is missing, even if assertion subject has expired" do
      # Subject NotOnOrAfter is an assertion replay-protection window (5–15 min),
      # not a session lifetime. SLO must not be blocked just because the short-lived
      # assertion window has closed — the user's SSO session may still be active.
      not_on_or_after = DateTime.utc_now() |> DateTime.add(-8, :hour) |> DateTime.to_iso8601()

      assertion = %Samly.Assertion{
        subject: %{notonorafter: not_on_or_after},
        authn: %{}
      }

      result = StateUtil.validate_logout_assertion_expiry(assertion)
      assert result == :valid
    end

    test "is :valid when session_not_on_or_after is missing and assertion subject has not expired" do
      not_on_or_after = DateTime.utc_now() |> DateTime.add(8, :hour) |> DateTime.to_iso8601()

      assertion = %Samly.Assertion{
        subject: %{notonorafter: not_on_or_after},
        authn: %{}
      }

      result = StateUtil.validate_logout_assertion_expiry(assertion)

      # Assert
      assert result == :valid
    end
  end
end
