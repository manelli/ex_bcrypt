defmodule ExBcryptTest do
  use ExUnit.Case
  doctest ExBcrypt

  test "ExBcrypt.salt" do
    assert is_bitstring(ExBcrypt.salt)
  end

  test "ExBcrypt.hash" do
    assert is_bitstring(ExBcrypt.hash("password"))
  end

  test "ExBcrypt.match" do
    password = "hunter2"
    hash = ExBcrypt.hash(password)

    assert ExBcrypt.match(password, hash)
    refute ExBcrypt.match("bad_pwd", hash)
  end

  test "ExBcrypt.change_factor" do
    password = "hunter2"
    hash = ExBcrypt.hash(password)

    assert is_bitstring(ExBcrypt.change_factor(password, hash, 6))
    assert_raise ArgumentError, fn ->
      ExBcrypt.change_factor("bad_pwd", hash, "new_pwd")
    end
  end

  test "ExBcrypt.change_password" do
    password = "hunter2"
    hash = ExBcrypt.hash(password)

    assert is_bitstring(ExBcrypt.change_password(password, hash, "new_pwd"))
    assert_raise ArgumentError, fn ->
      ExBcrypt.change_password("bad_pwd", hash, "new_pwd")
    end
  end

end
