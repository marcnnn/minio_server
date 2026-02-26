defmodule MinioServerTest do
  use ExUnit.Case
  doctest MinioServer

  defp base_config(extra \\ []) do
    [
      access_key_id: "test_key",
      secret_access_key: "test_secret",
      minio_executable: "/bin/false"
    ] ++ extra
  end

  defp get_child_spec(config) do
    {:ok, {_sup_flags, [child_spec]}} = MinioServer.init(config)
    {MuonTrap.Daemon, :start_link, [executable, cli_args, daemon_opts]} = child_spec.start
    %{executable: executable, cli_args: cli_args, daemon_opts: daemon_opts}
  end

  describe "TLS / certs_dir" do
    test "certs_dir is passed as --certs-dir" do
      %{cli_args: cli_args} = get_child_spec(base_config(certs_dir: "/path/to/certs"))

      assert "--certs-dir" in cli_args
      assert "/path/to/certs" in cli_args

      # Verify they appear consecutively
      idx = Enum.find_index(cli_args, &(&1 == "--certs-dir"))
      assert Enum.at(cli_args, idx + 1) == "/path/to/certs"
    end

    test "without certs_dir, no --certs-dir flag" do
      %{cli_args: cli_args} = get_child_spec(base_config())

      refute "--certs-dir" in cli_args
    end

    test "certs_dir works alongside console_address" do
      config = base_config(certs_dir: "/path/to/certs", console_address: ":9001")
      %{cli_args: cli_args} = get_child_spec(config)

      assert "--certs-dir" in cli_args
      assert "/path/to/certs" in cli_args
      assert "--console-address" in cli_args
      assert ":9001" in cli_args
    end
  end

  describe "ensure_certs" do
    @tag :tmp_dir
    test "generates valid PEM cert and key files", %{tmp_dir: tmp_dir} do
      certs_dir = Path.join(tmp_dir, "certs")

      MinioServer.ensure_certs(certs_dir, "127.0.0.1")

      cert_file = Path.join(certs_dir, "public.crt")
      key_file = Path.join(certs_dir, "private.key")

      assert File.exists?(cert_file)
      assert File.exists?(key_file)

      # Verify they're valid PEM
      cert_pem = File.read!(cert_file)
      key_pem = File.read!(key_file)

      assert [{:Certificate, cert_der, :not_encrypted}] = :public_key.pem_decode(cert_pem)
      assert [{:RSAPrivateKey, _key_der, :not_encrypted}] = :public_key.pem_decode(key_pem)

      # Verify the cert can be decoded
      cert = :public_key.pkix_decode_cert(cert_der, :otp)
      assert cert != nil
    end

    @tag :tmp_dir
    test "does not regenerate if certs already exist", %{tmp_dir: tmp_dir} do
      certs_dir = Path.join(tmp_dir, "certs")
      File.mkdir_p!(certs_dir)

      File.write!(Path.join(certs_dir, "public.crt"), "existing cert")
      File.write!(Path.join(certs_dir, "private.key"), "existing key")

      MinioServer.ensure_certs(certs_dir, "127.0.0.1")

      assert File.read!(Path.join(certs_dir, "public.crt")) == "existing cert"
      assert File.read!(Path.join(certs_dir, "private.key")) == "existing key"
    end

    @tag :tmp_dir
    test "regenerates if only cert exists but key is missing", %{tmp_dir: tmp_dir} do
      certs_dir = Path.join(tmp_dir, "certs")
      File.mkdir_p!(certs_dir)

      File.write!(Path.join(certs_dir, "public.crt"), "orphan cert")

      MinioServer.ensure_certs(certs_dir, "127.0.0.1")

      # Should have regenerated since private.key was missing
      cert_pem = File.read!(Path.join(certs_dir, "public.crt"))
      assert cert_pem != "orphan cert"
      assert [{:Certificate, _, :not_encrypted}] = :public_key.pem_decode(cert_pem)
    end

    @tag :tmp_dir
    test "generates cert with IPv6 SAN entry", %{tmp_dir: tmp_dir} do
      certs_dir = Path.join(tmp_dir, "certs")

      MinioServer.ensure_certs(certs_dir, "::1")

      cert_pem = File.read!(Path.join(certs_dir, "public.crt"))
      assert [{:Certificate, cert_der, :not_encrypted}] = :public_key.pem_decode(cert_pem)
      cert = :public_key.pkix_decode_cert(cert_der, :otp)
      assert cert != nil
    end

    @tag :tmp_dir
    test "generates cert with hostname SAN entry", %{tmp_dir: tmp_dir} do
      certs_dir = Path.join(tmp_dir, "certs")

      MinioServer.ensure_certs(certs_dir, "minio.local")

      cert_pem = File.read!(Path.join(certs_dir, "public.crt"))
      assert [{:Certificate, cert_der, :not_encrypted}] = :public_key.pem_decode(cert_pem)
      cert = :public_key.pkix_decode_cert(cert_der, :otp)
      assert cert != nil
    end
  end

  describe "Admin.host_env (via alias_export)" do
    test "uses http scheme without certs_dir" do
      config = base_config()
      export = MinioServer.Admin.alias_export(config)

      assert export =~ "http://test_key:test_secret@127.0.0.1:9000"
      refute export =~ "https://"
    end

    test "uses https scheme when certs_dir is set" do
      config = base_config(certs_dir: "/path/to/certs")
      export = MinioServer.Admin.alias_export(config)

      assert export =~ "https://test_key:test_secret@127.0.0.1:9000"
    end

    test "uses custom host and port" do
      config = base_config(host: "192.168.1.10", port: 9999)
      export = MinioServer.Admin.alias_export(config)

      assert export =~ "192.168.1.10:9999"
    end
  end
end
