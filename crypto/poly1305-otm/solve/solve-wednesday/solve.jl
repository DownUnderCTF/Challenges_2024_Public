#! /usr/bin/env julia
@assert VERSION >= v"1.9.2"

#=
This challenge is based on Poly1305 used as a one time authenticator.

Poly1305 uses a pair of two 128-bit integers (r, s) as its secret key. This
implementation makes a mistake by passing a 128-bit key to Poly1305 rather than
a 256-bit key as expected. This means that although the first 128-bits of the
key (corresponding to r) are correctly read from a randomised buffer, the latter
128-bits (corresponding to s) are read from local stack variables pointing to
static data, and is constant between invocations in the same session. However
between different sessions the value of s will be slightly randomised due to
ASLR.

Notation: Let t_1, ... t_n be the authentication tags returned by the challenge
using keys (r_1, s), ... (r_n, s) and padded messages m_1, ... m_n. We can
obtain the flag if we can recover the last used key pair (r_n, s).

If we know a small range of possible values for s, then we can
efficiently recover r_n. To do this, we range over all possible values of s, and
given fixed s, solve the equations

  m_1 r_1 + s + k_1 2^128 = t_1 mod (2^130 -5) for k in [-4, 4]
  ...
  m_n r_n + s + k_n 2^128 = t_n mod (2^130 -5) for k in [-4, 4]

to find possible solutions for r_1, ... r_n. We will know that we have found
the correct s if all equations have a solution for r which satisfy the Poly1305
clamping requirements.

From local testing, we observe a few samples for s (notation is big-endian bitstring)
1. "00000000000000000101100110000001000000110100101100110000110000000000000000000000010110011000000100000011010010101110000001000000"
2. "00000000000000000101110110000100110111111011110010100000110000000000000000000000010111011000010011011111101111000101000001000000"
3. "00000000000000000101110110111011010101010110001101100000110000000000000000000000010111011011101101010101011000110001000001000000"
4. "00000000000000000110000010101000010101001101111001100000110000000000000000000000011000001010100001010100110111100001000001000000"

and find that possible values of s are of the form
s: "000000000000000001??????????????????????????????????000011000000000000000000000001??????????????????????????????????000001000000"

The unknown block in the lower 128-bits is always a constant offset from the
unknown block in the upper 128-bits, so there are roughly only 34 unknown bits.

Looking at the clamping requirements on r, we know that r is of the form
r: "0000??????????????????????????000000??????????????????????????000000??????????????????????????000000????????????????????????????"

And comparing, we have
s: "000000000000000001??????????????????????????????????000011000000000000000000000001??????????????????????????????????000001000000"
r: "0000??????????????????????????000000??????????????????????????000000??????????????????????????000000????????????????????????????"

So if we can choose m_i so that m_i = 2^-k mod p, then we have
  m_i * r_i ≈ (r_i >> k)  p,
and hence
  t_i = m_i * r_i ≈ (r_i >> k) + s.

Given such a t_i, we can "look through the holes" in r left by the clamping to
observe partial bits of s. Then once we have enough known bits of s, we can
apply our initial strategy above to solve for r and obtain a forgery.
=#

using Sockets
using ProgressBars
include("ChaCha20Poly1305.jl") # a pure julia ChaCha20Poly1305 implemenation
include("PartialIntegers.jl")  # support for partial integers

const TARGET_MESSAGE = b"I have broken Poly1305 one time MAC!"
const S_UPPER_SUB_S_LOWER = 0x0000000000005080 # upper bits of s are always a constant offset from the lower bits of s

# Struct to hold MACs returned by the challenge
struct Tag
  tag::UInt128
  message::Vector{UInt8}
  power::Int64
end

function Tag(tag::AbstractVector{UInt8}, message::AbstractVector{UInt8}, power::Int64)::Tag
  tag = only(reinterpret(UInt128, tag))
  Tag(tag, message, power)
end

# Known bits of s
const PARTIAL_S = PartialInteger(
"000000000000000001??????????????????????????????????000011000000000000000000000001??????????????????????????????????000001000000"
)

# Menuing
function writelineafter(conn::IO, delim::AbstractString, data::AbstractString)
  readuntil(conn, delim, keep = true)
  write(conn, data * "\n")
end

function menu(conn::IO, option::Int64)
  writelineafter(conn, "> ", "$option\n")
end

function get_mac(conn::IO, message::AbstractVector{UInt8})
  menu(conn, 1)
  writelineafter(conn, "message: ", bytes2hex(message))

  hex2bytes(readuntil(conn, "\n"))
end

function verify_mac(conn::IO, mac::AbstractVector{UInt8})::AbstractString
  menu(conn, 2)
  writelineafter(conn, "mac: ", bytes2hex(mac) * "\n")

  readuntil(conn, "\n")
end

function is_clamped(r::AbstractVector{UInt8})::Bool
  poly1305_clamp!(copy(r)) == r
end

function solve_poly_given_s(tag, s, message)
  rs = []

  coeff = evalpoly(F_p(256), [message; [0x01]])
  for k = -4:4
    rhs = F_p(tag) - F_p(s) + k * F_p(big(2)^128)
    r = lift(inv(coeff) * rhs)
    if r <= typemax(UInt128)
      r = reinterpret(UInt8, [UInt128(r)]) # coeff * coeff^-1 * r
      if is_clamped(r)
        push!(rs, r)
      end
    end
  end

  rs
end

function has_valid_sol(tag, s, message)
  !isempty(solve_poly_given_s(tag, s, message))
end

# powers k for which 2^-k mod p can be constructed as a poly1305 coefficient
const POWS = [1, 5, 9, 13, 17, 21, 25, 29, 33, 37, 41, 45, 49,
              53, 57, 61, 65, 69, 73, 77, 81, 85, 89, 93, 97,
              101, 105, 109, 113, 117, 121, 125, 129]

# N = number of queries for gathering information
# n = number of queries per power
# w = window size to look through
function main(; N = 40, n=4, w = 2)
  conn = connect("127.0.0.1", 1337)
  pows = POWS[1:fld(N, n)]

  # Collect tags which leak information about s
  alltags = []
  for power in pows
    tags = Tag[]
    # This message will become 2^-k mod p once Poly1305-padded.
    message = UInt8.(digits(lift(inv(F_p(big(2)^power))); base = 256))[1:16]
    for _ = 1:n
      tag = get_mac(conn, message)
      push!(tags, Tag(tag, message, power))
    end
    push!(alltags, tags)
  end

  # "Look through" the clamping window at leaked bits of s
  partial_s = PARTIAL_S
  for tags in alltags
    power = first(tags).power
    for basepoint in (63, 95)   # locations in r which are clamped
      for i = w:-1:0
      window = intersect((basepoint+power):(basepoint+power+i), 1:128)
        leaked_bits = map(t -> bitstring(t.tag)[window], tags)
        if allequal(leaked_bits)
          partial_s.bv[window] = coalesce.(
            partial_s.bv[window], # already known bits
            parse.(Int64, collect(only(unique(leaked_bits)))) # new bits
          )
          break
        end
      end
    end
  end
  s_lower = PartialInteger(partial_s.bv[65:end])

  # Brute force the remaining unknown bits of s
  tags = reduce(vcat, alltags)
  ss = Set()
  brutemap(s_lower, UInt64) do lower
    upper = lower + S_UPPER_SUB_S_LOWER
    s = (UInt128(upper) << 64) | lower
    if all(tag -> has_valid_sol(tag.tag, s, tag.message), tags)
      push!(ss, s)
    end
  end

  # Use the value of s we acquired to compute a MAC for the target message
  for s in ss
    tag = last(last(alltags))
    for r in solve_poly_given_s(tag.tag, s, tag.message)
      key = [r; reinterpret(UInt8, [s])]
      mac = poly1305(key, TARGET_MESSAGE)
      flag = verify_mac(conn, mac)
      if occursin("DUCTF", flag)
        @show flag
      end
    end
  end

end

if abspath(PROGRAM_FILE) == @__FILE__
  main()
end
