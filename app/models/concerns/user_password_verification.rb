# frozen_string_literal: true

require 'argon2'
require 'bcrypt'

# Prepended on User so this wins over Devise / devise_token_auth #valid_password?.
module UserPasswordVerification
  def valid_password?(password_to_check)
    return false if encrypted_password.blank? || password_to_check.blank?

    hash = encrypted_password.to_s

    if hash.start_with?('$argon2')
      verify_password_argon2(password_to_check, hash)
    elsif bcrypt_digest?(hash)
      verify_password_bcrypt(password_to_check, hash)
    else
      verify_password_argon2(password_to_check, hash)
    end
  rescue StandardError => e
    Rails.logger.error "Erro ao verificar senha: #{e.class} - #{e.message}"
    false
  end

  private

  def bcrypt_digest?(hash)
    hash.match?(/\A\$2[aby]\$\d{2}\$/o)
  end

  def verify_password_argon2(password_to_check, hash)
    Argon2::Password.verify_password(password_to_check, hash)
  end

  def verify_password_bcrypt(password_to_check, hash)
    BCrypt::Password.new(hash) == password_to_check
  rescue BCrypt::Errors::InvalidHash
    false
  end
end
