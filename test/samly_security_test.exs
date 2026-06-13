defmodule Samly.SecurityTest do
  @moduledoc """
  Security-focused tests covering:
  - Expired assertion rejection for login (get_active_assertion semantics)
  - Expired assertion tolerance for SLO logout (get_assertion semantics)
  - Deletion of existing assertion before issuing a new AuthnRequest (re-auth)
  """

  use ExUnit.Case, async: true

  import Plug.Test
  import Plug.Conn

  alias Samly.State.StateUtil
  alias Samly.{Assertion, State, Subject}

  defp session_conn() do
    opts =
      Plug.Session.init(
        store: :cookie,
        key: "_samly_security_test_session",
        encryption_salt: "security enc salt",
        signing_salt: "security signing salt",
        key_length: 64
      )

    State.init(State.Session)

    conn(:get, "/")
    |> Plug.Session.call(opts)
    |> fetch_session()
  end

  defp expired_assertion() do
    not_on_or_after = DateTime.utc_now() |> DateTime.add(-1, :hour) |> DateTime.to_iso8601()

    %Assertion{
      subject: %Subject{notonorafter: not_on_or_after},
      authn: %{}
    }
  end

  defp valid_assertion() do
    not_on_or_after = DateTime.utc_now() |> DateTime.add(8, :hour) |> DateTime.to_iso8601()

    %Assertion{
      subject: %Subject{notonorafter: not_on_or_after},
      authn: %{}
    }
  end

  # ---------------------------------------------------------------------------
  # A. Expired assertion is REJECTED for login (get_active_assertion semantics)
  # ---------------------------------------------------------------------------

  describe "login assertion expiry (get_active_assertion semantics)" do
    test "expired assertion is rejected: validate_login_assertion_expiry returns :expired" do
      assertion = expired_assertion()
      result = StateUtil.validate_login_assertion_expiry(assertion)
      assert result == :expired
    end

    test "valid assertion is accepted: validate_login_assertion_expiry returns :valid" do
      assertion = valid_assertion()
      result = StateUtil.validate_login_assertion_expiry(assertion)
      assert result == :valid
    end

    test "expired assertion stored in Session store is present via get_assertion but rejected by validate_login_assertion_expiry" do
      conn = session_conn()
      assertion = expired_assertion()
      assertion_key = {"idp1", "user_expired_login"}

      conn = State.put_assertion(conn, assertion_key, assertion)

      # State.get_assertion returns the raw assertion regardless of expiry
      retrieved = State.get_assertion(conn, assertion_key)
      assert %Assertion{} = retrieved

      # The active-assertion check (used in auth_handler send_signin_req) rejects it
      assert StateUtil.validate_login_assertion_expiry(retrieved) == :expired
    end

    test "valid assertion stored in Session store passes both retrieval and login expiry check" do
      conn = session_conn()
      assertion = valid_assertion()
      assertion_key = {"idp1", "user_valid_login"}

      conn = State.put_assertion(conn, assertion_key, assertion)

      retrieved = State.get_assertion(conn, assertion_key)
      assert %Assertion{} = retrieved
      assert StateUtil.validate_login_assertion_expiry(retrieved) == :valid
    end
  end

  # ---------------------------------------------------------------------------
  # B. Expired assertion is ALLOWED for SLO logout (get_assertion semantics)
  # ---------------------------------------------------------------------------

  describe "logout assertion expiry (SLO get_assertion semantics)" do
    test "assertion expired by subject but valid by session_not_on_or_after: validate_logout_assertion_expiry returns :valid" do
      # Subject expired 1 hour ago, but session is still active for 7 more hours
      not_on_or_after = DateTime.utc_now() |> DateTime.add(-1, :hour) |> DateTime.to_iso8601()

      session_not_on_or_after =
        DateTime.utc_now() |> DateTime.add(7, :hour) |> DateTime.to_iso8601()

      assertion = %Assertion{
        subject: %Subject{notonorafter: not_on_or_after},
        authn: %{"session_not_on_or_after" => session_not_on_or_after}
      }

      result = StateUtil.validate_logout_assertion_expiry(assertion)
      assert result == :valid
    end

    test "assertion expired by subject, no session_not_on_or_after: validate_logout_assertion_expiry returns :valid" do
      # Subject NotOnOrAfter is a replay-protection window, not a session lifetime.
      # When SessionNotOnOrAfter is absent (the common case), SLO must not be blocked.
      assertion = expired_assertion()
      result = StateUtil.validate_logout_assertion_expiry(assertion)
      assert result == :valid
    end

    test "fully expired assertion (both subject and session expired) is still retrievable from state store" do
      # This tests that State.get_assertion does NOT filter by expiry — it's the caller's
      # responsibility (sp_handler handle_logout_request) to check expiry for SLO.
      conn = session_conn()
      not_on_or_after = DateTime.utc_now() |> DateTime.add(-2, :hour) |> DateTime.to_iso8601()

      session_not_on_or_after =
        DateTime.utc_now() |> DateTime.add(-1, :hour) |> DateTime.to_iso8601()

      assertion = %Assertion{
        subject: %Subject{notonorafter: not_on_or_after},
        authn: %{"session_not_on_or_after" => session_not_on_or_after}
      }

      assertion_key = {"idp1", "user_expired_slo"}
      conn = State.put_assertion(conn, assertion_key, assertion)

      # State.get_assertion returns the assertion even though it is fully expired;
      # the SLO handler decides whether to accept it via validate_logout_assertion_expiry.
      retrieved = State.get_assertion(conn, assertion_key)
      assert %Assertion{} = retrieved

      # For SLO, this is expired (both subject and session)
      assert StateUtil.validate_logout_assertion_expiry(retrieved) == :expired
    end

    test "assertion with subject expired but active session is still accepted for SLO logout" do
      conn = session_conn()
      not_on_or_after = DateTime.utc_now() |> DateTime.add(-1, :hour) |> DateTime.to_iso8601()

      session_not_on_or_after =
        DateTime.utc_now() |> DateTime.add(7, :hour) |> DateTime.to_iso8601()

      assertion = %Assertion{
        subject: %Subject{notonorafter: not_on_or_after},
        authn: %{"session_not_on_or_after" => session_not_on_or_after}
      }

      assertion_key = {"idp1", "user_slo_active_session"}
      conn = State.put_assertion(conn, assertion_key, assertion)

      retrieved = State.get_assertion(conn, assertion_key)
      assert %Assertion{} = retrieved

      # Logout is still valid because session_not_on_or_after is in the future
      assert StateUtil.validate_logout_assertion_expiry(retrieved) == :valid
    end
  end

  # ---------------------------------------------------------------------------
  # C. Delete assertion on re-auth
  # ---------------------------------------------------------------------------

  describe "delete assertion on re-auth" do
    test "assertion is deleted from state before issuing a new AuthnRequest" do
      # This mirrors the logic in AuthHandler.send_signin_req/1:
      # when an existing assertion is present but expired (or the user re-authenticates),
      # State.delete_assertion/2 is called before redirecting to the IdP.
      conn = session_conn()
      assertion = valid_assertion()
      assertion_key = {"idp1", "user_reauth"}

      # Simulate an existing logged-in session
      conn = State.put_assertion(conn, assertion_key, assertion)
      assert %Assertion{} = State.get_assertion(conn, assertion_key)

      # Simulate the re-auth path: delete assertion before issuing a new AuthnRequest
      conn = State.delete_assertion(conn, assertion_key)

      # Assertion must no longer be retrievable
      assert is_nil(State.get_assertion(conn, assertion_key))
    end

    test "deleting a non-existent assertion does not raise" do
      conn = session_conn()
      assertion_key = {"idp1", "nonexistent_user"}

      # Should not raise even when nothing is stored
      conn = State.delete_assertion(conn, assertion_key)
      assert is_nil(State.get_assertion(conn, assertion_key))
    end

    test "after re-auth delete, new assertion can be stored under the same key" do
      conn = session_conn()
      old_not_on_or_after = DateTime.utc_now() |> DateTime.add(1, :hour) |> DateTime.to_iso8601()

      old_assertion = %Assertion{
        subject: %Subject{notonorafter: old_not_on_or_after, name: "user1"},
        authn: %{"session_index" => "old-session"}
      }

      new_not_on_or_after = DateTime.utc_now() |> DateTime.add(8, :hour) |> DateTime.to_iso8601()

      new_assertion = %Assertion{
        subject: %Subject{notonorafter: new_not_on_or_after, name: "user1"},
        authn: %{"session_index" => "new-session"}
      }

      assertion_key = {"idp1", "user1"}

      # Store old assertion
      conn = State.put_assertion(conn, assertion_key, old_assertion)
      assert State.get_assertion(conn, assertion_key) == old_assertion

      # Delete on re-auth initiation
      conn = State.delete_assertion(conn, assertion_key)
      assert is_nil(State.get_assertion(conn, assertion_key))

      # New assertion from fresh authentication
      conn = State.put_assertion(conn, assertion_key, new_assertion)
      retrieved = State.get_assertion(conn, assertion_key)
      assert retrieved == new_assertion
      assert get_in(retrieved.authn, ["session_index"]) == "new-session"
    end
  end
end
