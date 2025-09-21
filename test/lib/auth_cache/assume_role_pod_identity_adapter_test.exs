defmodule ExAws.STS.AuthCache.AssumeRolePodIdentityAdapterTest do
  use ExUnit.Case, async: true
  alias ExAws.STS.AuthCache.AssumeRolePodIdentityAdapter

  import Mox

  @container_credentials_uri "http://169.254.170.2/v2/credentials/12345678-1234-1234-1234-123456789012"
  @authorization_token "Bearer token123"
  @expiration 30_000

  setup do
    token_path = Path.join(System.tmp_dir!(), "test_token_#{System.unique_integer()}")
    File.write!(token_path, @authorization_token)

    System.put_env("AWS_CONTAINER_CREDENTIALS_FULL_URI", @container_credentials_uri)
    System.put_env("AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE", token_path)

    on_exit(fn ->
      File.rm_rf(token_path)
      System.delete_env("AWS_CONTAINER_CREDENTIALS_FULL_URI")
      System.delete_env("AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE")
    end)
  end

  describe "when the config values are injected" do
    test "#adapt_auth_config" do
      config = %{
        container_credentials_uri: "http://custom.endpoint/credentials",
        container_authorization_token_file: create_token_file("custom_token"),
        http_client: ExAws.Request.HttpMock,
        json_codec: Jason
      }

      response_body = %{
        "AccessKeyId" => "AKIAIOSFODNN7EXAMPLE",
        "SecretAccessKey" => "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        "Token" => "session_token_example",
        "Expiration" => "2023-12-31T23:59:59Z"
      }

      ExAws.Request.HttpMock
      |> expect(:request, fn :get,
                             "http://custom.endpoint/credentials",
                             "",
                             [{"Authorization", "custom_token"}],
                             _opts ->
        {:ok, %{body: Jason.encode!(response_body)}}
      end)

      expected = %{
        access_key_id: "AKIAIOSFODNN7EXAMPLE",
        secret_access_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        security_token: "session_token_example",
        expiration: "2023-12-31T23:59:59Z"
      }

      assert expected == AssumeRolePodIdentityAdapter.adapt_auth_config(config, nil, @expiration)
    end
  end

  describe "when using environment variables" do
    test "#adapt_auth_config" do
      config = %{
        http_client: ExAws.Request.HttpMock,
        json_codec: Jason
      }

      response_body = %{
        "AccessKeyId" => "AKIAIOSFODNN7EXAMPLE",
        "SecretAccessKey" => "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        "Token" => "session_token_example",
        "Expiration" => "2023-12-31T23:59:59Z"
      }

      ExAws.Request.HttpMock
      |> expect(:request, fn :get,
                             @container_credentials_uri,
                             "",
                             [{"Authorization", @authorization_token}],
                             _opts ->
        {:ok, %{body: Jason.encode!(response_body)}}
      end)

      expected = %{
        access_key_id: "AKIAIOSFODNN7EXAMPLE",
        secret_access_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        security_token: "session_token_example",
        expiration: "2023-12-31T23:59:59Z"
      }

      assert expected == AssumeRolePodIdentityAdapter.adapt_auth_config(config, nil, @expiration)
    end
  end

  describe "when the HTTP request fails" do
    test "#adapt_auth_config returns error" do
      config = %{
        http_client: ExAws.Request.HttpMock,
        json_codec: Jason
      }

      ExAws.Request.HttpMock
      |> expect(:request, fn :get,
                             @container_credentials_uri,
                             "",
                             [{"Authorization", @authorization_token}],
                             _opts ->
        {:error, :timeout}
      end)

      assert {:error, :timeout} == AssumeRolePodIdentityAdapter.adapt_auth_config(config, nil, @expiration)
    end
  end

  describe "when the authorization token file does not exist" do
    test "#adapt_auth_config raises File.Error" do
      System.put_env("AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE", "./does_not_exist")

      config = %{
        http_client: ExAws.Request.HttpMock,
        json_codec: Jason
      }

      assert_raise File.Error, fn ->
        AssumeRolePodIdentityAdapter.adapt_auth_config(config, nil, @expiration)
      end
    end
  end

  describe "when the container credentials URI is not provided" do
    test "#adapt_auth_config returns empty map when env var is not set" do
      System.delete_env("AWS_CONTAINER_CREDENTIALS_FULL_URI")

      config = %{
        http_client: ExAws.Request.HttpMock,
        json_codec: Jason
      }

      expected = %{}

      assert expected == AssumeRolePodIdentityAdapter.adapt_auth_config(config, nil, @expiration)
    end

    test "#adapt_auth_config returns empty map when config URI is nil" do
      # Clear environment variable to ensure we're only testing config
      System.delete_env("AWS_CONTAINER_CREDENTIALS_FULL_URI")

      config = %{
        container_credentials_uri: nil,
        http_client: ExAws.Request.HttpMock,
        json_codec: Jason
      }

      expected = %{}

      assert expected == AssumeRolePodIdentityAdapter.adapt_auth_config(config, nil, @expiration)
    end
  end

  defp create_token_file(content) do
    path = Path.join(System.tmp_dir!(), "test_token_#{System.unique_integer()}")
    File.write!(path, content)
    path
  end
end
