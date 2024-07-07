require "doublehelix"

def randomly_replace(input_string, x, y)
  output_string = ""
  input_string.each_char do |char|
    if char == x && rand(5) == 0
      output_string += y
    else
      output_string += char
    end
  end
  return output_string
end


dna = doublehelix('puts"DUCTF{7H3_Mit0cHOndRi4_15_7he_P0wEr_HoUsE_of_DA_C3LL}"')

decayed_dna = randomly_replace(dna, "A", "\u0020")
decayed_dna = randomly_replace(decayed_dna, "T", "\u0020")
decayed_dna = randomly_replace(decayed_dna, "G", "\u0020")
decayed_dna = randomly_replace(decayed_dna, "C", "\u0020")
decayed_dna = randomly_replace(decayed_dna, "-", "\u0020")

puts decayed_dna