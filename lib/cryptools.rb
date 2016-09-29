require 'base64'

# Custom Error Class
CryptoolsError = Class.new(StandardError)

module Cryptools
  module Converters
    module_function

    def hex2str(hexStr)
      [hexStr].pack('H*')
    end
  
    def str2hex(str)
      str.unpack('H*').first
    end 

    def hex2bytes(hexStr)
      hex2str(hexStr).unpack('C*')
    end

    def bytes2hex(bytes)
      bytes.map{|b| b.to_s(16)}.join
    end
    
    def str2bytes(str)
      str.split('').map!{|c| c.ord}
    end
  end

  module Encoders
    module_function

    def b64_encode(str)
      Base64.strict_encode64(str)
    end

    def b64_decode(str)
      Base64.strict_decode64(str)
    end
  end

  module BitOperations
    module_function

    def xor_bytes(bytes1, bytes2)
      raise CryptoolsError, 'inputs are not the same length.' if bytes1.length != bytes2.length 

      bytes1.zip(bytes2).map{|(a, b)| a ^ b}
    end
  end

  module Cryptanalysis
    module_function

    def index_of_coincidence(input)
      fs = input.each_with_object(Hash.new(0)) { |word,counts| counts[word] += 1 }
      phiO = 0
      n = input.length
      coin_rtext = 0.0385

      fs.each {
        |key, f|
        phiO += f * (f - 1)
      }

      phiR = coin_rtext * n * (n - 1) 
      phiO / phiR
    end

    def english_freq_count(str)
      str.scan(/[ETAOIN SHRDLU]/i).length
    end
  end

  module Ciphers
    module_function

    def single_byte_repeating_xor(bytes, bytes_k)
      bytes.map{|b| b ^ bytes_k.first}
    end
  end
end
