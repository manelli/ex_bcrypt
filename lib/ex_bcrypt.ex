defmodule ExBcrypt do
  use Bitwise

  @moduledoc """
  bcrypt password hashing algorithm.
  """

  @spec salt(pos_integer) :: bitstring | Exception.t
  @doc """
  Generates a salt with a given work factor.

  The work factor defaults to 12 if no factor is given.
  The work factor should be between 4 and 31.
  """
  def salt(factor \\ 12)
  def salt(factor) when not(is_integer factor) or not(factor in 4..31),
    do: raise ArgumentError, "Work factor should be an integer between 4 and 31"
  def salt(factor) when factor in 4..31 do
    {:ok, salt} = :bcrypt.gen_salt(factor)
    List.to_string(salt)
  end

  @spec hash(binary, pos_integer) :: binary | Exception.t
  @doc """
  Hashes a given password with a given work factor.

  Bcrypt takes care of salting the hashes for you so this does not need to be
  done. The higher the work factor, the longer the password will take to be
  hashed and checked.
  The work factor defaults to 12 if no factor is given.
  The work factor should be between 4 and 31.
  """
  def hash(password, factor \\ 12) when is_binary(password) do
    {:ok, hash} = :bcrypt.hashpw(password, salt(factor))
    List.to_string(hash)
  end

  @spec match(binary, binary) :: boolean | Exception.t
  @doc """
  Compares a given password to a hash.

  Returns `true` if the password matches, `false` otherwise.
  The comparison is done in constant time (based on the hash length).
  """
  def match(password, hash) when is_binary(password) and is_binary(hash) do
    {:ok, res_hash} = :bcrypt.hashpw(password, String.to_char_list(hash))
    constant_compare(hash, List.to_string(res_hash))
  end

  @spec change_factor(binary, binary, pos_integer) :: bitstring | Exception.t
  @doc """
  Changes the work factor of a hash.

  If a given password matches a given hash, the password is re-hashed again
  using the new work_factor.
  """
  def change_factor(password, hash, factor) when is_binary(password) and is_binary(hash) do
    change_password(password, hash, password, factor)
  end

  @spec change_password(binary, binary, binary, pos_integer) :: bitstring | Exception.t
  @doc """
  Change a password, only if the previous one was given with it.

  If a given old password matches a given old hash, a new password
  is hashed using the work factor passed in as an argument. (Defaults to 12)
  """
  def change_password(old, hash, new, factor \\ 12) when is_binary(old) and is_binary(hash) and is_binary(new) do
    if match(old, hash) do
      hash(new, factor)
    else
      raise ArgumentError, "The old password doesn't match with the given hash"
    end
  end

  @spec time(pos_integer) :: {:ok, pos_integer, number} | Exception.t
  @doc """
  The time bcrypt takes to hash the string 'password'
  in relation with a given work factor.
  Returns a tuple in the form of:
  {:ok, work_factor, elapsed_time_in_ms}

  The work factor defaults to 12 if no factor is given.
  The work factor should be between 4 and 31.
  """
  def time(factor \\ 12) do
    {time, _} = :timer.tc(fn -> hash("password", factor) end)
    {:ok, factor, div(time, 1000)}
  end

  @spec constant_compare(binary, binary) :: boolean
  # Constant time string comparison.
  #
  # This function executes in constant time only
  # when the two strings have the same length.
  # It short-circuits when they have different lengths.
  #
  # Note that this does not prevent an attacker
  # from discovering the length of the strings.
  #
  # Returns `true` if the two strings are equal, `false` otherwise.
  defp constant_compare(x, y) when is_binary(x) and is_binary(y) do
    if byte_size(x) != byte_size(y) do
      false
    else
      x_list = String.to_char_list(x)
      y_list = String.to_char_list(y)

      0 == Enum.zip(x_list, y_list) |> Enum.reduce(0, fn({x_byte, y_byte}, acc) ->
        acc ||| bxor(x_byte, y_byte)
      end)
    end
  end

end
