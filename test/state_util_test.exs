defmodule Samly.StateUtilTest do
  @moduledoc false

  use ExUnit.Case, async: true

  alias Samly.State.StateUtil

  describe "validate_login_assertion_expiry/1" do
    test "is :expired when assertion is expired" do
      # Arrange
      not_on_or_after = DateTime.utc_now() |> DateTime.add(-8, :hour) |> DateTime.to_iso8601()

      session_not_on_or_after =
        DateTime.utc_now() |> DateTime.add(8, :hour) |> DateTime.to_iso8601()

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

    test "is :expired when session_not_on_or_after is missing and assertion subject has also expired" do
      # Arrange
      not_on_or_after = DateTime.utc_now() |> DateTime.add(-8, :hour) |> DateTime.to_iso8601()

      assertion = %Samly.Assertion{
        subject: %{notonorafter: not_on_or_after},
        authn: %{}
      }

      # Act
      result = StateUtil.validate_logout_assertion_expiry(assertion)

      # Assert
      assert result == :expired
    end

    test "is :valid when session_not_on_or_after is missing but assertion subject has not expired" do
      # Arrange
      not_on_or_after = DateTime.utc_now() |> DateTime.add(8, :hour) |> DateTime.to_iso8601()

      assertion = %Samly.Assertion{
        subject: %{notonorafter: not_on_or_after},
        authn: %{}
      }

      # Act
      result = StateUtil.validate_logout_assertion_expiry(assertion)

      # Assert
      assert result == :valid
    end
  end
end
