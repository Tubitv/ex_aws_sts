defmodule ExAws.STS.AuthCache.AssumeRolePodIdentityAdapter do
  @moduledoc """
  Provides a custom Adapter that intercepts ExAWS configuration
  which uses Pod Identity Tokens for authentication.
  """

  @behaviour ExAws.Config.AuthCache.AuthConfigAdapter

  @impl true
  def adapt_auth_config(config, _profile, _expiration) do
    case container_credentials_full_uri(config) do
      nil ->
        %{}

      uri ->
        http_client = config[:http_client] || ExAws.Request.Hackney
        json_codec = config[:json_codec] || Jason

        case http_client.request(:get, uri, "", [
               {"Authorization", container_authorization_token(config)}
             ], []) do
          {:ok, %{body: body}} ->
            values = json_codec.decode!(body)

            %{
              access_key_id: values["AccessKeyId"],
              secret_access_key: values["SecretAccessKey"],
              security_token: values["Token"],
              expiration: values["Expiration"]
            }

          {:error, reason} ->
            {:error, reason}
        end
    end
  end

  defp container_credentials_full_uri(config) do
    config[:container_credentials_uri] || System.get_env("AWS_CONTAINER_CREDENTIALS_FULL_URI")
  end

  defp container_authorization_token(config) do
    config
    |> container_authorization_token_file()
    |> File.read!()
  end

  defp container_authorization_token_file(config) do
    config[:container_authorization_token_file] ||
      System.get_env("AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE")
  end
end
