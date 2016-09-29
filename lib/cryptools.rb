require 'base64'

class CryptoolsError < StandardError
end

module Cryptools
	module Converters
		def hex2raw(input)
			return [input].pack('H*')
		end
	
		def raw2hex(input)
			return input.unpack('H*').first
		end	

		def hex2bytes(input)
			return hex2raw(input).unpack('C*')
		end

		def bytes2hex(input)
			return input.map{|x| x.to_s(16) }.join
		end
		
		def str2bytes(str)
			str.split('').map!{|c| c.ord}
		end


		module_function :hex2raw
		module_function :raw2hex
		module_function :hex2bytes
		module_function :bytes2hex
		module_function :str2bytes
	end

	module Encoders
		def b64_encode(input)
			return Base64.strict_encode64(input)
		end

		def b64_decode(input)
			return Bas64.strict_decode64(input)
		end
		
		module_function :b64_encode
		module_function :b64_decode
	end

	module BitOperations
		def xor_bytes(input1, input2)
			raise CryptoolsError, 'inputs are not the same length.' if input1.length != input2.length	

			return input1.zip(input2).map{|(a, b)| a ^ b}
		end
	
		module_function :xor_bytes
	end

	module Cryptanalysis
		def single_xor_bytes(input, xbyte)
			len = input.length
			xbytes = []

			for i in 0..(len - 1) 
				xbytes.push(xbyte.first)	
			end	

			return BitOperations.xor_bytes(input, xbytes)
		end
		
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
			return phiO / phiR
		end

		def english_freq_count(str)
			str.scan(/[ETAOIN SHRDLU]/i).length
		end

		module_function :english_freq_count
		module_function :index_of_coincidence
		module_function :single_xor_bytes
	end
	module Ciphers
		def single_byte_repeating_xor(ary_bytes, ary_key)
			ary_bytes.map{|b| b ^ ary_key.first}
		end

		module_function :single_byte_repeating_xor
	end
end
