using AbstractAlgebra

const P = BigInt(2)^130 - 5
const F_p = GF(P)

function quarter_round(a::UInt32, b::UInt32, c::UInt32, d::UInt32)
    #! format: off
    a += b; d ⊻= a; d = bitrotate(d, 16);
    c += d; b ⊻= c; b = bitrotate(b, 12);
    a += b; d ⊻= a; d = bitrotate(d, 8);
    c += d; b ⊻= c; b = bitrotate(b, 7);
    #! format: on

  a, b, c, d
end

function quarter_round!(state::AbstractMatrix{UInt32}, a_idx, b_idx, c_idx, d_idx)
  state[a_idx], state[b_idx], state[c_idx], state[d_idx] =
    quarter_round(state[a_idx], state[b_idx], state[c_idx], state[d_idx])

  state
end

function chacha20_block_checkdims(key, nonce, block_count)
  if sizeof(key) * 8 != 256 || sizeof(nonce) * 8 != 96 || sizeof(block_count) * 8 != 32
    false
  end

  true
end

function chacha20_block_init_state(
  key::AbstractVector{UInt8},
  nonce::AbstractVector{UInt8},
  block_count::AbstractVector{UInt8},
)
  key = reinterpret(UInt32, key)
  nonce = reinterpret(UInt32, nonce)
  block_count = reinterpret(UInt32, block_count)

  UInt32[
    0x61707865 0x3320646e 0x79622d32 0x6b206574
    transpose(key[1:4])
    transpose(key[5:8])
    transpose(block_count) transpose(nonce)
  ]
end

function chacha20_block(
  key::AbstractVector{UInt8},
  nonce::AbstractVector{UInt8},
  block_count::AbstractVector{UInt8},
)
  chacha20_block_checkdims(key, nonce, block_count) || throw(
    ArgumentError(
      "Expected 256 bit key, 96 bit nonce, 32 bit block_count, passed as 32-bit little endian integers",
    ),
  )

  state = chacha20_block_init_state(key, nonce, block_count)
  working_state = copy(state)
  rm_view = transpose(working_state) # row-major indexed matrix
  for _ = 1:10
    chacha20_block_innerblock!(rm_view)
  end
  state += working_state

  serialize(state)
end

function chacha20_block_innerblock!(rm_view::AbstractMatrix{UInt32})
  # using 1-based row-major indexes
  quarter_round!(rm_view, 1, 5, 9, 13)
  quarter_round!(rm_view, 2, 6, 10, 14)
  quarter_round!(rm_view, 3, 7, 11, 15)
  quarter_round!(rm_view, 4, 8, 12, 16)
  quarter_round!(rm_view, 1, 6, 11, 16)
  quarter_round!(rm_view, 2, 7, 12, 13)
  quarter_round!(rm_view, 3, 8, 9, 14)
  quarter_round!(rm_view, 4, 5, 10, 15)
end

function serialize(chacha_state::AbstractMatrix{UInt32})
  reshape(reinterpret(UInt8, transpose(chacha_state)), 64)
end

function chacha20(
  key::AbstractVector{UInt8},
  block_count::AbstractVector{UInt8},
  nonce::AbstractVector{UInt8},
  plaintext::AbstractVector{UInt8},
)
  chacha20_block_checkdims(key, nonce, block_count)
  base_count = only(reinterpret(UInt32, block_count))
  encrypted_message = UInt8[]
  for (i::UInt32, message_block) in enumerate(Iterators.partition(plaintext, 64))
    counter = reinterpret(UInt8, [base_count + (i - one(UInt32))])
    key_stream = chacha20_block(key, nonce, counter)
    block = collect(x ⊻ y for (x, y) in zip(key_stream, message_block))
    append!(encrypted_message, block)
  end

  encrypted_message
end

function poly1305_clamp!(r::AbstractVector{UInt8})
  # 1-based index again
  r[4] &= 0x0f
  r[8] &= 0x0f
  r[12] &= 0x0f
  r[16] &= 0x0f

  r[5] &= 0xfc
  r[9] &= 0xfc
  r[13] &= 0xfc

  r
end

function poly1305_checkdims(key)
  if sizeof(key) * 8 != 256
    false
  end

  true
end

function poly1305_prepare_key(key::AbstractVector{UInt8})
  r, s = key[1:16], key[17:end]
  poly1305_clamp!(r)
  r = F_p(only(reinterpret(UInt128, r)))
  s = BigInt(only(reinterpret(UInt128, s)))

  return r, s
end

function poly1305_poly(message::AbstractVector{UInt8}, r::FinFieldElem)
  acc = zero(F_p)

  for m in Iterators.partition(message, 16)
    n = evalpoly(F_p(256), [m; [0x01]])
    acc += n
    acc *= r
  end

  acc
end

function poly1305(key::AbstractVector{UInt8}, message::AbstractVector{UInt8})
  poly1305_checkdims(key) || throw(
    ArgumentError(
      "Expected 256 bit key, 96 bit nonce, 32 bit block_count, passed as 32-bit little endian integers",
    ),
  )

  r, s = poly1305_prepare_key(key)

  acc = poly1305_poly(message, r)
  acc = lift(acc) + s

  lower128 = acc & ~UInt128(0)

  convert.(UInt8, digits(lower128, base = 256, pad = 16))
end

function poly1305_key_gen(key::AbstractVector{UInt8}, nonce::AbstractVector{UInt8})
  counter = reinterpret(UInt8, [0x00000000])
  block = chacha20_block(key, nonce, counter)

  block[1:32]          # first 256 bits
end

function aead_chacha20_poly1305_message_construct(
  ciphertext::AbstractVector{UInt8},
  aad::AbstractVector{UInt8},
)
  padding1 = fill(0x00, mod(-length(aad), 16))
  padding2 = fill(0x00, mod(-length(ciphertext), 16))
  aad_length = reinterpret(UInt8, [length(aad)])
  ciphertext_length = reinterpret(UInt8, [length(ciphertext)])

  UInt8[aad; padding1; ciphertext; padding2; aad_length; ciphertext_length]
end

function aead_chacha20_poly1305(
  key::AbstractVector{UInt8},
  nonce::AbstractVector{UInt8},
  plaintext::AbstractVector{UInt8},
  aad::AbstractVector{UInt8},
)
  poly1305_key = poly1305_key_gen(key, nonce)
  counter = reinterpret(UInt8, [0x00000001])
  ciphertext = chacha20(key, counter, nonce, plaintext)

  message = aead_chacha20_poly1305_message_construct(ciphertext, aad)
  tag = poly1305(poly1305_key, message)

  return tag, ciphertext
end
