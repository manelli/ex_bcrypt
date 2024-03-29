# ExBcrypt

**Elixir wrapper for the OpenBSD bcrypt password hashing algorithm.**

[![Build Status](https://travis-ci.org/manelli/ex_bcrypt.svg?branch=master)](https://travis-ci.org/manelli/ex_bcrypt)

## Installation

  1. Add ex_bcrypt to your list of dependencies in `mix.exs`:

```elixir
  def deps do
    [{:ex_bcrypt, "~> 0.0.1"}]
  end
```

  2. Ensure ex_bcrypt is started before your application:

```elixir
  def application do
    [applications: [:ex_bcrypt]]
  end
```

## Documentation

API documentation is available at [https://hexdocs.pm/ex_bcrypt](https://hexdocs.pm/ex_bcrypt)
