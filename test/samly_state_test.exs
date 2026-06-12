defmodule Samly.StateTest do
  use ExUnit.Case, async: true

  import Plug.Test
  import Plug.Conn

  alias Samly.State.StateUtil

  describe "With Session Cache" do
    setup do
      opts =
        Plug.Session.init(
          store: :cookie,
          key: "_samly_state_test_session",
          encryption_salt: "salty enc",
          signing_salt: "salty signing",
          key_length: 64
        )

      Samly.State.init(Samly.State.Session)

      conn =
        conn(:get, "/")
        |> Plug.Session.call(opts)
        |> fetch_session()

      [conn: conn]
    end

    test "put/get assertion", %{conn: conn} do
      not_on_or_after = DateTime.utc_now() |> DateTime.add(8, :hour) |> DateTime.to_iso8601()
      assertion = %Samly.Assertion{subject: %{notonorafter: not_on_or_after}}
      assertion_key = {"idp1", "name1"}
      conn = Samly.State.put_assertion(conn, assertion_key, assertion)
      assert assertion == Samly.State.get_assertion(conn, assertion_key)
    end

    test "get failure for unknown assertion key", %{conn: conn} do
      assertion = %Samly.Assertion{}
      assertion_key = {"idp1", "name1"}
      conn = Samly.State.put_assertion(conn, assertion_key, assertion)
      assert is_nil(Samly.State.get_assertion(conn, {"idp1", "name2"}))
    end

    test "get failure for expired assertion key", %{conn: conn} do
      # Arrange
      assertion = %Samly.Assertion{}
      assertion_key = {"idp1", "name1"}

      # Act
      result =
        conn
        |> Samly.State.put_assertion(assertion_key, assertion)
        |> Samly.State.get_assertion(assertion_key)
        |> StateUtil.validate_login_assertion_expiry()

      # Assert
      assert result == :expired
    end

    test "delete assertion", %{conn: conn} do
      not_on_or_after = DateTime.utc_now() |> DateTime.add(8, :hour) |> DateTime.to_iso8601()
      assertion = %Samly.Assertion{subject: %{notonorafter: not_on_or_after}}
      assertion_key = {"idp1", "name1"}
      conn = Samly.State.put_assertion(conn, assertion_key, assertion)
      assert assertion == Samly.State.get_assertion(conn, assertion_key)
      conn = Samly.State.delete_assertion(conn, assertion_key)
      assert is_nil(Samly.State.get_assertion(conn, assertion_key))
    end
  end

  describe "With ETS Cache" do
    setup do
      Samly.State.init(Samly.State.ETS)
      [conn: conn(:get, "/")]
    end

    test "put/get assertion", %{conn: conn} do
      not_on_or_after = DateTime.utc_now() |> DateTime.add(8, :hour) |> DateTime.to_iso8601()
      assertion = %Samly.Assertion{subject: %{notonorafter: not_on_or_after}}
      assertion_key = {"idp1", "name1"}
      conn = Samly.State.put_assertion(conn, assertion_key, assertion)
      assert assertion == Samly.State.get_assertion(conn, assertion_key)
    end

    test "get failure for unknown assertion key", %{conn: conn} do
      assertion = %Samly.Assertion{}
      assertion_key = {"idp1", "name1"}
      conn = Samly.State.put_assertion(conn, assertion_key, assertion)
      assert is_nil(Samly.State.get_assertion(conn, {"idp1", "name2"}))
    end

    test "get failure for expired assertion key", %{conn: conn} do
      # Arrange
      assertion = %Samly.Assertion{}
      assertion_key = {"idp1", "name1"}

      # Act
      result =
        conn
        |> Samly.State.put_assertion(assertion_key, assertion)
        |> Samly.State.get_assertion(assertion_key)
        |> StateUtil.validate_login_assertion_expiry()

      # Assert
      assert result == :expired
    end

    test "delete assertion", %{conn: conn} do
      not_on_or_after = DateTime.utc_now() |> DateTime.add(8, :hour) |> DateTime.to_iso8601()
      assertion = %Samly.Assertion{subject: %{notonorafter: not_on_or_after}}
      assertion_key = {"idp1", "name1"}
      conn = Samly.State.put_assertion(conn, assertion_key, assertion)
      assert assertion == Samly.State.get_assertion(conn, assertion_key)
      conn = Samly.State.delete_assertion(conn, assertion_key)
      assert is_nil(Samly.State.get_assertion(conn, assertion_key))
    end
  end

  describe "With Redis Cache" do
    @moduletag :redis
    @describetag :async_false

    setup do
      # Generate unique connection name for this test
      redis_name = :"redix_test_#{System.unique_integer([:positive])}"

      # Start Redix connection for testing
      {:ok, redix_pid} = Redix.start_link(host: "localhost", port: 6379, name: redis_name)

      # Initialize state with Redis
      Samly.State.init(Samly.State.Redis, redis_name: redis_name, key_prefix: "samly:test:")

      # Cleanup function to stop Redix and flush test keys
      on_exit(fn ->
        # Only flush if connection is still alive
        if Process.alive?(redix_pid) do
          Redix.command(redis_name, ["KEYS", "samly:test:*"])
          |> case do
            {:ok, [_ | _] = keys} ->
              Redix.command(redis_name, ["DEL" | keys])

            _ ->
              :ok
          end
        end

        if Process.alive?(redix_pid) do
          Process.exit(redix_pid, :normal)
        end
      end)

      [conn: conn(:get, "/"), redis_name: redis_name]
    end

    test "put/get assertion", %{conn: conn} do
      not_on_or_after = DateTime.utc_now() |> DateTime.add(8, :hour) |> DateTime.to_iso8601()
      assertion = %Samly.Assertion{subject: %{notonorafter: not_on_or_after}}
      assertion_key = {"idp1", "name1"}
      conn = Samly.State.put_assertion(conn, assertion_key, assertion)
      assert assertion == Samly.State.get_assertion(conn, assertion_key)
    end

    test "get failure for unknown assertion key", %{conn: conn} do
      assertion = %Samly.Assertion{}
      assertion_key = {"idp1", "name1"}
      conn = Samly.State.put_assertion(conn, assertion_key, assertion)
      assert is_nil(Samly.State.get_assertion(conn, {"idp1", "name2"}))
    end

    test "get failure for expired assertion key", %{conn: conn} do
      # Arrange
      assertion = %Samly.Assertion{}
      assertion_key = {"idp1", "name1"}

      # Act
      result =
        conn
        |> Samly.State.put_assertion(assertion_key, assertion)
        |> Samly.State.get_assertion(assertion_key)
        |> StateUtil.validate_login_assertion_expiry()

      # Assert
      assert result == :expired
    end

    test "delete assertion", %{conn: conn} do
      not_on_or_after = DateTime.utc_now() |> DateTime.add(8, :hour) |> DateTime.to_iso8601()
      assertion = %Samly.Assertion{subject: %{notonorafter: not_on_or_after}}
      assertion_key = {"idp1", "name1"}
      conn = Samly.State.put_assertion(conn, assertion_key, assertion)
      assert assertion == Samly.State.get_assertion(conn, assertion_key)
      conn = Samly.State.delete_assertion(conn, assertion_key)
      assert is_nil(Samly.State.get_assertion(conn, assertion_key))
    end

    test "TTL functionality", %{conn: conn, redis_name: redis_name} do
      # Test with short TTL
      Samly.State.init(Samly.State.Redis,
        redis_name: redis_name,
        key_prefix: "samly:test:",
        ttl: 1
      )

      assertion = %Samly.Assertion{}
      assertion_key = {"idp1", "ttl_test"}
      conn = Samly.State.put_assertion(conn, assertion_key, assertion)

      # Should exist immediately
      assert %Samly.Assertion{} = Samly.State.get_assertion(conn, assertion_key)

      # Wait for expiration
      Process.sleep(1100)

      # Should be expired
      assert is_nil(Samly.State.get_assertion(conn, assertion_key))
    end

    test "handles nil assertion_key gracefully", %{conn: conn} do
      # get_assertion with nil should return nil
      assert is_nil(Samly.State.get_assertion(conn, nil))

      # delete_assertion with nil should return conn unchanged
      assert ^conn = Samly.State.delete_assertion(conn, nil)
    end
  end
end
