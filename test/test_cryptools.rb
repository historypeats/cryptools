require 'minitest/autorun'
require 'cryptools'


class CryptoolsTest < Minitest::Test
  
  # Converters
  def test_hex2str
    t = '41'
    assert_equal('A', Cryptools::Converters.hex2str(t))  
  end 

  def test_str2hex
    t = 'A'
    assert_equal('41', Cryptools::Converters.str2hex(t))
  end

  def test_hex2bytes
    t = '41'
    assert_equal([65], Cryptools::Converters.hex2bytes(t))
  end

  def test_bytes2hex
    t = [65]
    assert_equal('41', Cryptools::Converters.bytes2hex(t))
  end

  def test_str2bytes
    t = 'AA'
    assert_equal([65, 65], Cryptools::Converters.str2bytes(t))
  end

  # Encoders
  def test_b64_encode
    t = 'A'
    assert_equal('QQ==', Cryptools::Encoders.b64_encode(t))
  end

  def test_b64_decode
    t = 'QQ=='
    assert_equal('A', Cryptools::Encoders.b64_decode(t))
  end

  # BitOperations
  def test_xor_bytes
    t1 = [65, 65]
    t2 = [67, 67]
    assert_equal([2, 2], Cryptools::BitOperations.xor_bytes(t1, t2))
  end

  # Cryptanalysis
  def test_english_freq_count
    t = 'This is some sentence. Can you determine if its english?'
    assert_equal(47, Cryptools::Cryptanalysis.english_freq_count(t))
  end

  # Ciphers

  def test_single_byte_repeating_xor
    t = Cryptools::Converters.str2bytes('This is some secret message')
    k = [65]
    assert_equal([21, 41, 40, 50, 97, 40, 50, 97, 50, 46, 44, 36, 97, 50, 36, 34, 51, 36, 53, 97, 44, 36, 50, 50, 32, 38, 36], Cryptools::Ciphers.single_byte_repeating_xor(t, k))
  end

end
