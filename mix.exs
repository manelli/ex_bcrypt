defmodule Secure.Mixfile do
  use Mix.Project

  def project do
    [app: :ex_bcrypt,
     version: "0.0.1",
     elixir: "~> 1.2",
     build_embedded: Mix.env == :prod,
     start_permanent: Mix.env == :prod,
     deps: deps,
     description: "Elixir wrapper for the OpenBSD bcrypt password hashing algorithm",
     source_url: "https://github.com/manelli/ex_bcrypt/",
     package: package]
  end

  def application do
    [applications: [:logger, :bcrypt]]
  end

  def deps do
    [{:bcrypt, "~> 0.5.0-p3a"},
     {:earmark, "~> 0.2", only: :docs},
     {:ex_doc, "~> 0.11", only: :docs}]
  end

  defp package do
    [
     maintainers: ["Martin Manelli"],
     licenses: ["MIT"],
     links: %{"GitHub" => "https://github.com/manelli/ex_bcrypt",
              "Docs" => "https://hexdocs.pm/ex_bcrypt"}]
  end

end
