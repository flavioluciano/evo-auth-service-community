# frozen_string_literal: true

namespace :evo_auth do
  desc 'Redefine a senha de um utilizador no auth (desenvolvimento/recuperação). EMAIL e PASSWORD obrigatórios.'
  task reset_password: :environment do
    email = ENV.fetch('EMAIL', nil)&.strip&.downcase
    password = ENV.fetch('PASSWORD', nil)

    if email.blank? || password.blank?
      abort 'Usage: EMAIL=user@example.com PASSWORD=novasenha bundle exec rake evo_auth:reset_password'
    end

    user = User.from_email(email)
    abort "User not found: #{email}" unless user

    user.skip_confirmation!
    user.password = password
    user.password_confirmation = password
    user.save!

    puts "Password updated for #{email}"
  end

  desc 'Testa validação de senha para um email (sem mostrar a senha nos logs). EMAIL e PASSWORD obrigatórios.'
  task verify_login: :environment do
    email = ENV.fetch('EMAIL', nil)&.strip&.downcase
    password = ENV.fetch('PASSWORD', nil)

    if email.blank? || password.blank?
      abort 'Usage: EMAIL=user@example.com PASSWORD=senha bundle exec rake evo_auth:verify_login'
    end

    user = User.from_email(email)
    if user.nil?
      puts 'user_found=false'
      exit 1
    end

    hash = user.encrypted_password.to_s
    prefix =
      if hash.start_with?('$argon2')
        'argon2'
      elsif hash.match?(/\A\$2[aby]\$/o)
        'bcrypt'
      else
        'unknown'
      end

    ok = user.valid_password?(password)
    puts "user_found=true hash_kind=#{prefix} valid_password=#{ok} enc_blank=#{hash.blank?}"
    exit(ok ? 0 : 1)
  end
end
