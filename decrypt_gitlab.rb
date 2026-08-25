require 'openssl'
require 'base64'

# SELECT id, username, email, encrypted_otp_secret, encrypted_otp_secret_iv, encrypted_otp_secret_salt FROM users;
otp_key_base = "<from secrets.json>"
encrypted = Base64.decode64("<encrypted_otp_secret>")
iv = Base64.decode64("<iv>")
salt = Base64.decode64("<salt>")

key = OpenSSL::PKCS5.pbkdf2_hmac_sha1(otp_key_base, salt, 2000, 32)
cipher = OpenSSL::Cipher.new('aes-256-cbc')
cipher.decrypt
cipher.key = key
cipher.iv = iv
puts cipher.update(encrypted) + cipher.final
