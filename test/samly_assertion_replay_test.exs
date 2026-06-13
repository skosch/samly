defmodule Samly.AssertionReplayTest do
  # async: false — exercises a named ETS table shared across the suite.
  use ExUnit.Case, async: false

  alias Samly.AssertionReplay

  describe "check_and_record/4" do
    setup do
      table = :ets.new(:replay_test_table, [:set, :public])
      on_exit(fn -> :ets.info(table) != :undefined && :ets.delete(table) end)
      {:ok, table: table}
    end

    test "accepts a digest the first time it is seen", %{table: table} do
      assert :ok = AssertionReplay.check_and_record(table, "digest-a", 1000, 500)
    end

    test "rejects a replay of a still-live digest", %{table: table} do
      assert :ok = AssertionReplay.check_and_record(table, "digest-a", 1000, 500)

      assert {:error, :duplicate_assertion} =
               AssertionReplay.check_and_record(table, "digest-a", 1000, 600)
    end

    test "accepts again once the recorded entry has expired", %{table: table} do
      assert :ok = AssertionReplay.check_and_record(table, "digest-a", 1000, 500)

      # now (1001) is past the recorded expiry (1000): no longer a duplicate
      assert :ok = AssertionReplay.check_and_record(table, "digest-a", 2000, 1001)

      # the entry was refreshed with the new expiry, so it is live again
      assert {:error, :duplicate_assertion} =
               AssertionReplay.check_and_record(table, "digest-a", 2000, 1500)
    end

    test "treats the expiry boundary as still-live (strict greater-than)", %{table: table} do
      assert :ok = AssertionReplay.check_and_record(table, "digest-a", 1000, 500)

      # now == expiry: not strictly greater, so the entry is considered expired
      assert :ok = AssertionReplay.check_and_record(table, "digest-a", 1000, 1000)
    end

    test "tracks distinct digests independently", %{table: table} do
      assert :ok = AssertionReplay.check_and_record(table, "digest-a", 1000, 500)
      assert :ok = AssertionReplay.check_and_record(table, "digest-b", 1000, 500)

      assert {:error, :duplicate_assertion} =
               AssertionReplay.check_and_record(table, "digest-a", 1000, 600)

      assert {:error, :duplicate_assertion} =
               AssertionReplay.check_and_record(table, "digest-b", 1000, 600)
    end
  end

  describe "table/0" do
    test "creates the named table on demand and is idempotent" do
      assert :samly_seen_assertions = AssertionReplay.table()
      refute :ets.info(:samly_seen_assertions) == :undefined
      # Calling again must not raise even though the table already exists.
      assert :samly_seen_assertions = AssertionReplay.table()
    end
  end
end
