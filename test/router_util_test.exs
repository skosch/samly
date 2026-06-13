defmodule Samly.RouterUtilTest do
  use ExUnit.Case, async: false

  alias Samly.RouterUtil

  describe "relative_target_url?/1" do
    test "accepts nil and empty (defaults to root later)" do
      assert RouterUtil.relative_target_url?(nil)
      assert RouterUtil.relative_target_url?("")
    end

    test "accepts site-relative paths" do
      assert RouterUtil.relative_target_url?("/")
      assert RouterUtil.relative_target_url?("/Home")
      assert RouterUtil.relative_target_url?("/a/b?c=d#e")
    end

    test "rejects absolute URLs" do
      refute RouterUtil.relative_target_url?("https://evil.example.com/")
      refute RouterUtil.relative_target_url?("http://evil.example.com")
    end

    test "rejects protocol-relative URLs" do
      refute RouterUtil.relative_target_url?("//evil.example.com/path")
    end

    test "rejects bare or scheme-relative values" do
      refute RouterUtil.relative_target_url?("evil.example.com")
      refute RouterUtil.relative_target_url?("javascript:alert(1)")
    end

    test "allows absolute URLs when explicitly opted in" do
      Application.put_env(:samly, :allow_absolute_target_urls, true)
      on_exit(fn -> Application.delete_env(:samly, :allow_absolute_target_urls) end)

      assert RouterUtil.relative_target_url?("https://trusted.example.com/landing")
    end
  end
end
