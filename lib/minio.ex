defmodule MinioServer do
  @moduledoc """
  Documentation for `MinioServer`.

  ## Usage

      # Config can be used directly with :ex_aws/:ex_aws_s3
      s3_config = [
        access_key_id: "minio_key",
        secret_access_key: "minio_secret",
        scheme: "http://",
        region: "local",
        host: "127.0.0.1",
        port: 9000,
        # Minio specific
        minio_path: "data" # Defaults to minio in your mix project
      ]

      # HTTPS (with TLS) — required for SSE-C encryption
      # Self-signed certs are auto-generated if both public.crt and 
      # private.key don't exist in the certs_dir yet.
      s3_config = [
        access_key_id: "minio_key",
        secret_access_key: "minio_secret",
        scheme: "https://",
        region: "local",
        host: "127.0.0.1",
        port: 9000,
        minio_path: "data",
        certs_dir: "/path/to/certs"
      ]

      # In a supervisor
      children = [
        {MinioServer, s3_config}
      ]

      # or manually
      {:ok, _} = MinioServer.start_link(s3_config)

  """
  use Supervisor
  require Logger
  require Record
  alias MinioServer.Config

  # OTP ASN.1 records for self-signed certificate generation
  @otp_pub_key "public_key/include/OTP-PUB-KEY.hrl"

  Record.defrecordp(
    :otp_tbs_certificate,
    :OTPTBSCertificate,
    Record.extract(:OTPTBSCertificate, from_lib: @otp_pub_key)
  )

  Record.defrecordp(
    :signature_algorithm,
    :SignatureAlgorithm,
    Record.extract(:SignatureAlgorithm, from_lib: @otp_pub_key)
  )

  Record.defrecordp(:validity, :Validity, Record.extract(:Validity, from_lib: @otp_pub_key))

  Record.defrecordp(
    :spki,
    :OTPSubjectPublicKeyInfo,
    Record.extract(:OTPSubjectPublicKeyInfo, from_lib: @otp_pub_key)
  )

  Record.defrecordp(
    :pk_algorithm,
    :PublicKeyAlgorithm,
    Record.extract(:PublicKeyAlgorithm, from_lib: @otp_pub_key)
  )

  Record.defrecordp(
    :cert_extension,
    :Extension,
    Record.extract(:Extension, from_lib: @otp_pub_key)
  )

  Record.defrecordp(
    :attr_type_and_value,
    :AttributeTypeAndValue,
    Record.extract(:AttributeTypeAndValue, from_lib: @otp_pub_key)
  )

  @type architecture :: String.t()
  @type version :: String.t()

  def start_link(init_arg) do
    host = Keyword.get(init_arg, :host, "127.0.0.1")

    if certs_dir = Keyword.get(init_arg, :certs_dir) do
      ensure_certs(certs_dir, host)
    end

    Supervisor.start_link(__MODULE__, init_arg, name: __MODULE__)
  end

  @impl true
  def init(init_arg) do
    key = Keyword.fetch!(init_arg, :access_key_id)
    secret = Keyword.fetch!(init_arg, :secret_access_key)
    host = Keyword.get(init_arg, :host, "127.0.0.1")
    port = Keyword.get(init_arg, :port, 9000)
    ui = Keyword.get(init_arg, :ui, true)
    minio_path = Keyword.get(init_arg, :minio_path, Path.expand("minio", "."))
    minio_executable = Keyword.get(init_arg, :minio_executable, Config.minio_executable())

    additional_args =
      Enum.reduce(init_arg, [], fn
        {:console_address, addr}, acc -> [["--console-address", addr] | acc]
        {:certs_dir, dir}, acc -> [["--certs-dir", dir] | acc]
        _, acc -> acc
      end)
      |> Enum.reverse()
      |> List.flatten()

    children = [
      {MuonTrap.Daemon,
       [
         minio_executable,
         [
           "server",
           minio_path,
           "--json",
           "--quiet",
           "--address",
           "#{host}:#{port}" | additional_args
         ],
         [
           log_output: :info,
           log_prefix: "[minio] ",
           env: [
             {"MINIO_ACCESS_KEY", key},
             {"MINIO_SECRET_KEY", secret},
             {"MINIO_BROWSER", if(ui, do: "on", else: "off")}
           ]
         ]
       ]}
    ]

    Logger.info("Running minio server at #{host}:#{port}")

    if ui do
      ui_port = if port = Keyword.get(init_arg, :console_address), do: port, else: ":#{port}"
      scheme = if Keyword.has_key?(init_arg, :certs_dir), do: "https", else: "http"
      Logger.info("Access minio server UI at #{scheme}://#{host}#{ui_port}")
    end

    Supervisor.init(children, strategy: :one_for_one)
  end

  @doc "A list of all the available architectures downloadable."
  @spec available_architectures :: [MinioServer.architecture()]
  defdelegate available_architectures(), to: MinioServer.Config

  @doc """
  Download the binary for a selected architecture

  ## Opts

  * `:force` - Replace already existing binaries. Defaults to `false`.
  * `:timeout` - Time the download is allowed to take. Defaults to `:infinity`.

  """
  @spec download_server(MinioServer.architecture(), keyword()) :: :exists | :ok | :timeout
  defdelegate download_server(arch, opts \\ []), to: MinioServer.DownloaderServer, as: :download

  @spec download_client(MinioServer.architecture(), keyword()) :: :exists | :ok | :timeout
  defdelegate download_client(arch, opts \\ []), to: MinioServer.DownloaderClient, as: :download

  @doc false
  def ensure_certs(certs_dir, host) do
    cert_file = Path.join(certs_dir, "public.crt")
    key_file = Path.join(certs_dir, "private.key")

    unless File.exists?(cert_file) and File.exists?(key_file) do
      File.mkdir_p!(certs_dir)

      key = :public_key.generate_key({:rsa, 2048, 65537})
      {:RSAPrivateKey, _, modulus, pub_exp, _, _, _, _, _, _, _} = key

      rdn =
        {:rdnSequence, [[attr_type_and_value(type: {2, 5, 4, 3}, value: {:utf8String, host})]]}

      now = DateTime.utc_now()
      not_after = DateTime.add(now, 3650 * 86400, :second)

      tbs =
        otp_tbs_certificate(
          version: :v3,
          serialNumber: :crypto.strong_rand_bytes(16) |> :binary.decode_unsigned(),
          signature:
            signature_algorithm(
              algorithm: {1, 2, 840, 113_549, 1, 1, 11},
              parameters: :NULL
            ),
          issuer: rdn,
          validity:
            validity(
              notBefore: {:utcTime, format_utc_time(now)},
              notAfter: {:utcTime, format_utc_time(not_after)}
            ),
          subject: rdn,
          subjectPublicKeyInfo:
            spki(
              algorithm:
                pk_algorithm(
                  algorithm: {1, 2, 840, 113_549, 1, 1, 1},
                  parameters: :NULL
                ),
              subjectPublicKey: {:RSAPublicKey, modulus, pub_exp}
            ),
          extensions: [
            cert_extension(
              extnID: {2, 5, 29, 17},
              critical: false,
              extnValue: build_san_entries(host)
            )
          ]
        )

      cert_der = :public_key.pkix_sign(tbs, key)

      key_pem = :public_key.pem_encode([:public_key.pem_entry_encode(:RSAPrivateKey, key)])
      cert_pem = :public_key.pem_encode([{:Certificate, cert_der, :not_encrypted}])

      File.write!(key_file, key_pem)
      File.write!(cert_file, cert_pem)

      Logger.info("Generated self-signed TLS certs for MinIO at #{certs_dir}")
    end
  end

  defp build_san_entries(host) do
    ip_or_dns =
      case :inet.parse_address(String.to_charlist(host)) do
        {:ok, {a, b, c, d}} ->
          [{:iPAddress, <<a, b, c, d>>}]

        {:ok, {a, b, c, d, e, f, g, h}} ->
          [{:iPAddress, <<a::16, b::16, c::16, d::16, e::16, f::16, g::16, h::16>>}]

        {:error, _} ->
          [{:dNSName, String.to_charlist(host)}]
      end

    ip_or_dns ++ [{:dNSName, ~c"localhost"}]
  end

  defp format_utc_time(datetime) do
    :lists.flatten(
      :io_lib.format(~c"~2..0B~2..0B~2..0B~2..0B~2..0B~2..0BZ", [
        rem(datetime.year, 100),
        datetime.month,
        datetime.day,
        datetime.hour,
        datetime.minute,
        datetime.second
      ])
    )
  end
end
