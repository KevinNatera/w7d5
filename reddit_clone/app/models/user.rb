class User < ApplicationRecord
    validates :username,:password_digest, :session_token, presence: true 
    validates :session_token, uniqueness: true 
    validates :password, length: { minimum: 6 }
    
    attr_reader :password 
    before_validation :ensure_session_token 

    def password=(password)
        self.password_digest = BCrypt::Password.create(password)
        @password = password
    end 

    def is_password?(password)
        password_object = BCrypt::Password.new(self.password_digest)
        password_object.is_password?(password)
    end

    def generate_session_token 
        SecureRandom::urlsafe_base64
    end

    def reset_session_token!
        self.session_token = generate_session_token
        self.save! 
        self.session_token
    end

    def ensure_session_token
        self.session_token ||= generate_session_token
    end
end