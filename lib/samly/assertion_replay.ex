defmodule Samly.AssertionReplay do
  @moduledoc false

  # Single-use assertion enforcement (Web SSO profile §4.1.4.5).
  #
  # esaml accepts the same signed SAML response more than once. This module
  # records the canonical digest of every accepted response and rejects any
  # later response carrying the same digest while the original assertion is
  # still within its validity window (`esaml:stale_time/1`). Entries are kept
  # until overwritten; an expired entry no longer counts as a duplicate, so
  # the cache self-heals on collision and never falsely rejects a fresh login.

  require Samly.Esaml

  @table :samly_seen_assertions

  @doc """
  Rejects `response_xml` if its digest has already been seen and is still live.

  `assertion_rec` is the esaml assertion record, used to derive the expiry.
  """
  @spec check(tuple(), tuple()) :: :ok | {:error, :duplicate_assertion}
  def check(response_xml, assertion_rec) do
    digest = :xmerl_dsig.digest(response_xml)
    expiry_secs = :esaml.stale_time(assertion_rec)
    check_and_record(table(), digest, expiry_secs, now_gregorian_secs())
  end

  @doc """
  Pure core of `check/2`: looks up `digest` in `table` and records it.

  A digest seen with an expiry still in the future is a duplicate. Otherwise the
  digest is (re)recorded with `expiry_secs` and accepted. All times are in
  Gregorian seconds.
  """
  @spec check_and_record(:ets.tab(), binary(), integer(), integer()) ::
          :ok | {:error, :duplicate_assertion}
  def check_and_record(table, digest, expiry_secs, now_secs) do
    case :ets.lookup(table, digest) do
      [{^digest, seen_expiry}] when seen_expiry > now_secs ->
        {:error, :duplicate_assertion}

      _ ->
        :ets.insert(table, {digest, expiry_secs})
        :ok
    end
  end

  @doc """
  Ensures the backing ETS table exists and returns its name.

  Safe to call concurrently and repeatedly.
  """
  @spec table() :: :ets.tab()
  def table do
    if :ets.info(@table) == :undefined do
      try do
        :ets.new(@table, [:set, :public, :named_table])
      rescue
        ArgumentError -> :ok
      end
    end

    @table
  end

  defp now_gregorian_secs do
    :calendar.datetime_to_gregorian_seconds(:calendar.universal_time())
  end
end
