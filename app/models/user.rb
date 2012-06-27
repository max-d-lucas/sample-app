class User < ActiveRecord::Base
    attr_accessible :email, :name, :password, :password_confirmation
    has_secure_password

    before_save { |user| user.email = email.downcase }
    before_validation { |user| user.email = email.downcase }

    VALID_EMAIL_REGEX = /^((([a-z]|\d|[!#\$%&'\*\+\-\/=\?\^_`{\|}~]|[\u00A0-\uD7FF\uF900-\uFDCF\uFDF0-\uFFEF])+(\.([a-z]|\d|[!#\$%&'\*\+\-\/=\?\^_`{\|}~]|[\u00A0-\uD7FF\uF900-\uFDCF\uFDF0-\uFFEF])+)*)|((\x22)((((\x20|\x09)*(\x0d\x0a))?(\x20|\x09)+)?(([\x01-\x08\x0b\x0c\x0e-\x1f\x7f]|\x21|[\x23-\x5b]|[\x5d-\x7e]|[\u00A0-\uD7FF\uF900-\uFDCF\uFDF0-\uFFEF])|(\\([\x01-\x09\x0b\x0c\x0d-\x7f]|[\u00A0-\uD7FF\uF900-\uFDCF\uFDF0-\uFFEF]))))*(((\x20|\x09)*(\x0d\x0a))?(\x20|\x09)+)?(\x22)))@((([a-z]|\d|[\u00A0-\uD7FF\uF900-\uFDCF\uFDF0-\uFFEF])|(([a-z]|\d|[\u00A0-\uD7FF\uF900-\uFDCF\uFDF0-\uFFEF])([a-z]|\d|-|\.|_|~|[\u00A0-\uD7FF\uF900-\uFDCF\uFDF0-\uFFEF])*([a-z]|\d|[\u00A0-\uD7FF\uF900-\uFDCF\uFDF0-\uFFEF])))\.)+(([a-z]|[\u00A0-\uD7FF\uF900-\uFDCF\uFDF0-\uFFEF])|(([a-z]|[\u00A0-\uD7FF\uF900-\uFDCF\uFDF0-\uFFEF])([a-z]|\d|-|\.|_|~|[\u00A0-\uD7FF\uF900-\uFDCF\uFDF0-\uFFEF])*([a-z]|[\u00A0-\uD7FF\uF900-\uFDCF\uFDF0-\uFFEF])))\.?$/i
    validates :name, presence: true, length: {maximum:255, minimum:3}
    validates :email, presence: true, format: { with: VALID_EMAIL_REGEX}, uniqueness: true
    validates :password, presence: true, length: {maximum:75, minimum:8}
    validates :password_confirmation, presence: true

    validate :meets_secure_password_rules, :meets_name_rules

    def meets_secure_password_rules
        errors.add(:password, "can not be the same as your email address.") if password.downcase==email.downcase
        errors.add(:password, "can not be the same as your name.") if password.downcase==name.downcase
        errors.add(:password, "Password must have at least 1 uppercase character.") unless password.match(/[[:upper:]]+?/)
        errors.add(:password, "Password must have at least 1 lowercase character.") unless password.match(/[[:lower:]]+?/)
        errors.add(:password, "Password must have at least 1 numeric character.") unless password.match(/[[:digit:]]+?/)
        password.match(/[\W]+?/) {|schar| errors.add(:password, "Password may not have special characters, " + schar.to_s + " found" ) }
    end  

    def meets_name_rules
        name.match(/[^[:alnum:][:blank:]\_~\[\]\?!\(\)\.\-'@]+?/) {|schar| errors.add(:name, "may not have special characters, " + schar.to_s + " found" ) }
    end    
end
# == Schema Information
#
# Table name: users
#
#  id         :integer         not null, primary key
#  name       :string(255)
#  email      :string(255)
#  created_at :datetime        not null
#  updated_at :datetime        not null
#

