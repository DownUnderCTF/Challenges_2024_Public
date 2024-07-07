file_path = 'publish/dna.rb'

first_pass = ""

if File.exist?(file_path)
  File.readlines(file_path).drop(2).each do |line|
    stripped_line = line.gsub(" ", "").strip

    # Case: AT
    candidate = stripped_line
    if ["AT", "TA", "GC", "CG"].include?(candidate)
      first_pass += candidate + "\n"
      next
    end

    # Case: A---T
    candidate = stripped_line.gsub("-", "")
    if ["AT", "TA", "GC", "CG"].include?(candidate)
      first_pass += candidate + "\n"
      next
    end

    candidate = stripped_line.gsub(/-+/, "-")
    # Case: A--
    case candidate
    when "A-"
      first_pass += "AT\n"
      next
    when "T-"
      first_pass += "TA\n"
      next
    when "G-"
      first_pass += "GC\n"
      next
    when "C-"
      first_pass += "CG\n"
      next
    end

    # Case: --A
    case candidate
    when "-A"
      first_pass += "TA\n"
      next
    when "-T"
      first_pass += "AT\n"
      next
    when "-G"
      first_pass += "CG\n"
      next
    when "-C"
      first_pass += "GC\n"
      next
    end

    # Case: A\n
    candidate = line[-2]
    case candidate
    when "A"
      first_pass += "TA\n"
      next
    when "T"
      first_pass += "AT\n"
      next
    when "G"
      first_pass += "CG\n"
      next
    when "C"
      first_pass += "GC\n"
      next
    end

    # Case: A \n
    candidate = line.strip
    case candidate
    when "A"
      first_pass += "AT\n"
      next
    when "T"
      first_pass += "TA\n"
      next
    when "G"
      first_pass += "GC\n"
      next
    when "C"
      first_pass += "CG\n"
      next
    end

    # Case: -
    first_pass += "missing\n"
  end
else
  puts "File not found: #{file_path}"
end

# puts first_pass

def generate_combinations(lines)
  missing_indices = lines.each_index.select { |i| lines[i] == "missing" }
  total_combinations = ["AT","TA", "GC", "CG"].repeated_permutation(missing_indices.size).to_a
  combinations = []

  total_combinations.each do |perm|
    new_lines = lines.dup
    missing_indices.each_with_index do |index, i|
      new_lines[index] = perm[i]
    end
    combinations << new_lines
  end

  combinations
end


lines = first_pass.split("\n")

combinations = generate_combinations(lines)

count = 0
combinations.each do |comb|
  code = "require \"doublehelix\"\n" + comb.join("\n")
  File.open("candidate.rb", 'w') { |file| file.write(code) }

  output=`ruby candidate.rb 2>/dev/null`

  begin
    if output.match?(/\A[\p{Graph}\t\n\r ]*\z/) # Ensure it's only printable characters
      puts output
    end
  rescue
  end

  # warn "Count: #{count}"
  count += 1
end