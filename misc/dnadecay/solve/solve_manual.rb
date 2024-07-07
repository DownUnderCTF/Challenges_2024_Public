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
puts "require \"doublehelix\""
puts first_pass