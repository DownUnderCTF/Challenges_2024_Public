# Big endian partial integer
struct PartialInteger
  bv::Vector{Union{Int64, Missing}}
end

function PartialInteger(bitstring::AbstractString)::PartialInteger
  bv = Vector{Union{Int64, Missing}}()
  for c in bitstring
    if c == '0'
      push!(bv, 0)
    elseif c == '1'
      push!(bv, 1)
    else
      push!(bv, missing)
    end
  end

  PartialInteger(bv)
end

function Base.merge(a::PartialInteger, b::PartialInteger)::PartialInteger
  @assert length(a.bv) == length(b.bv)
  PartialInteger(coalesce.(a.bv, b.bv))
end

function brutemap(f::Function, p::PartialInteger, T::Type)
  bv = reverse(p.bv)


  unknown_idxs = findall(ismissing.(bv)) .- 1
  stop = length(unknown_idxs)
  pbar = ProgressBar(total=2^stop)
  curr = evalpoly(T(2), coalesce.(bv, 0))

  function brute_rec(f::Function, curr, idx, pbar)
    if idx > stop
      f(curr)
      update(pbar)
      return
    end

    brute_rec(f, curr, idx+1, pbar)

    mask = one(T) << unknown_idxs[idx]
    brute_rec(f, curr | mask, idx+1, pbar)
  end

  brute_rec(f, curr, 1, pbar)
end
