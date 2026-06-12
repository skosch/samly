defmodule Samly.State.Redis do
  @moduledoc """
  Stores SAML assertion in Redis.

  This provider uses Redis to keep the authenticated SAML assertions from IdP.
  It supports both direct Redix connections and custom Redis client modules.

  ## Options

  +   `:redis_module` - Redis client module (optional)
                        Value must be an atom (module name)
                        Defaults to `Redix`
                        When using a custom module, it must implement `command/1` or `command/2`
  +   `:redis_name` - Redix connection name (optional, only used with Redix)
                      Value must be an atom
                      Defaults to `:redix`
  +   `:key_prefix` - Prefix for Redis keys (optional)
                      Value must be a string
                      Defaults to `"samly:assertion:"`
  +   `:ttl` - Time to live in seconds for assertions (optional)
               Value must be a positive integer
               Defaults to `3600`

  ## Configuration Examples

  ### Using Redix directly (default)

      config :samly, Samly.State,
        opts: [
          redis_name: :my_redix,
          key_prefix: "samly:assertion:",
          ttl: 60
        ]

  ### Using a custom Redis module (e.g., App.Redis with connection pool)

      config :samly, Samly.State,
        opts: [
          redis_module: App.Redis,
          key_prefix: "samly:assertion:",
          ttl: 60
        ]
  """

  alias Samly.Assertion

  @behaviour Samly.State.Store

  @default_redis_module Redix
  @default_redis_name :redix
  @default_key_prefix "samly:assertion:"
  @default_ttl 3600

  @impl Samly.State.Store
  def init(opts) do
    redis_module = Keyword.get(opts, :redis_module, @default_redis_module)
    redis_name = Keyword.get(opts, :redis_name, @default_redis_name)
    key_prefix = Keyword.get(opts, :key_prefix, @default_key_prefix)
    ttl = Keyword.get(opts, :ttl, @default_ttl)

    if not is_atom(redis_module) do
      raise "Samly.State.Redis redis_module must be an atom: #{inspect(redis_module)}"
    end

    if not is_atom(redis_name) do
      raise "Samly.State.Redis redis_name must be an atom: #{inspect(redis_name)}"
    end

    if not is_binary(key_prefix) do
      raise "Samly.State.Redis key_prefix must be a string: #{inspect(key_prefix)}"
    end

    if ttl != nil and (not is_integer(ttl) or ttl <= 0) do
      raise "Samly.State.Redis ttl must be a positive integer or nil: #{inspect(ttl)}"
    end

    [
      redis_module: redis_module,
      redis_name: redis_name,
      key_prefix: key_prefix,
      ttl: ttl
    ]
  end

  @impl Samly.State.Store
  def get_assertion(_conn, nil, _opts), do: nil

  def get_assertion(_conn, assertion_key, opts) do
    key_prefix = Keyword.fetch!(opts, :key_prefix)
    redis_key = build_redis_key(key_prefix, assertion_key)

    case redis_command(opts, ["GET", redis_key]) do
      {:ok, nil} ->
        nil

      {:ok, binary} when is_binary(binary) ->
        binary
        |> Base.decode64!()
        |> :erlang.binary_to_term([:safe])

      {:error, reason} ->
        raise "Failed to get assertion from Redis: #{inspect(reason)}"
    end
  end

  @impl Samly.State.Store
  def put_assertion(conn, assertion_key, %Assertion{} = assertion, opts) do
    key_prefix = Keyword.fetch!(opts, :key_prefix)
    ttl = Keyword.get(opts, :ttl)
    redis_key = build_redis_key(key_prefix, assertion_key)

    encoded_assertion =
      assertion
      |> :erlang.term_to_binary()
      |> Base.encode64()

    command =
      case ttl do
        nil -> ["SET", redis_key, encoded_assertion]
        ttl when is_integer(ttl) -> ["SETEX", redis_key, to_string(ttl), encoded_assertion]
      end

    case redis_command(opts, command) do
      {:ok, "OK"} ->
        conn

      {:error, reason} ->
        raise "Failed to put assertion to Redis: #{inspect(reason)}"
    end
  end

  @impl Samly.State.Store
  def delete_assertion(conn, nil, _opts), do: conn

  def delete_assertion(conn, assertion_key, opts) do
    key_prefix = Keyword.fetch!(opts, :key_prefix)
    redis_key = build_redis_key(key_prefix, assertion_key)

    case redis_command(opts, ["DEL", redis_key]) do
      {:ok, _} ->
        conn

      {:error, reason} ->
        raise "Failed to delete assertion from Redis: #{inspect(reason)}"
    end
  end

  defp redis_command(opts, command) do
    redis_module = Keyword.fetch!(opts, :redis_module)

    if redis_module == Redix do
      # Use Redix with connection name
      redis_name = Keyword.fetch!(opts, :redis_name)
      redis_module.command(redis_name, command)
    else
      # Use custom module (e.g., App.Redis) without connection name
      redis_module.command(command)
    end
  end

  defp build_redis_key(prefix, {idp_id, name_id}) do
    "#{prefix}#{idp_id}:#{name_id}"
  end
end
