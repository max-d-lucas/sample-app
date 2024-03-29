require 'spec_helper'

describe User do
    before do
        @user = User.new(name: "Example User", email: "user@example.com", password:"Password1", password_confirmation:"Password1") 
    end

    subject { @user }

    describe "user has properties" do
        it { should respond_to(:name) }
        it { should respond_to(:email) }
        it { should respond_to(:password_digest) }    
        it { should respond_to(:password) }    
        it { should respond_to(:password_confirmation) }    
        it { should respond_to(:remember_token) }
        it { should respond_to(:authenticate) } 

        it { should be_valid }  
    end
    describe "when password is not present" do
      before { @user.password = @user.password_confirmation = " " }
      it { should_not be_valid }
      after { @user.password = @user.password_confirmation = "Password1" }
    end
    describe "when password doesn't match confirmation" do
      before { @user.password_confirmation = "mismatch" }
      it { should_not be_valid }
      after { @user.password = @user.password_confirmation = "Password1" }
    end    
    describe "when password confirmation is nil" do
      before { @user.password_confirmation = nil }
      it { should_not be_valid }
      after { @user.password_confirmation = @user.password }
    end    
    describe "with a password that's too short" do
      before { @user.password = @user.password_confirmation = "Aa12345" }
      it { should be_invalid }
      after { @user.password = @user.password_confirmation = "Password1" }
    end    
    describe "with a password that's too long" do
      before { @user.password = @user.password_confirmation = "Aa1" * 26 }
      it { should be_invalid }
      after { @user.password = @user.password_confirmation = "Password1" }
    end        
    describe "with a password that's not mixed case, all lower" do
      before { @user.password = @user.password_confirmation = "1a" * 10 }
      it { should be_invalid }
      after { @user.password = @user.password_confirmation = "Password1" }
    end        
    describe "with a password that's not mixed case, all upper" do
      before { @user.password = @user.password_confirmation = "1A" * 10 }
      it { should be_invalid }
      after { @user.password = @user.password_confirmation = "Password1" }
    end        
    describe "with a password that's has no alpha characters" do
      before { @user.password = @user.password_confirmation = "1" * 10 }
      it { should be_invalid }
      after { @user.password = @user.password_confirmation = "Password1" }
    end        
    describe "with a password that's has no numeric characters" do
      before { @user.password = @user.password_confirmation = "Aa" * 5 }
      it { should be_invalid } 
      after { @user.password = @user.password_confirmation = "Password1" }
    end        
    describe "with a password that's has invalid characters" do
      before { @user.password = @user.password_confirmation = "Aa1!@#^&*()_+" }
      it { should be_invalid }
      after { @user.password = @user.password_confirmation = "Password1" }
    end        
    describe "with a password that matches email" do
      before { @user.password = @user.password_confirmation = @user.email }
      it { should be_invalid }
      after { @user.password = @user.password_confirmation = "Password1" }
    end        

    
    describe "when name is not present" do
        before { @user.name = " " }
        it { should_not be_valid }
        after { @user.name ="Example User" }
    end    

    describe "when name has special characters" do
        it "should not be valid" do
            names = %w[Bob# Jim: Ted$ Fred% Jake^ Slim&]
            names.each do |invalid_name|
                @user.name = invalid_name
                @user.should_not be_valid
            end      
        end
        after { @user.name ="Example User" }
    end    

    describe "when name has allowed non alpha characters" do
        it "should be valid" do
            names = %w[Bob! Jim( Ted) Fred- Jake. Slim?]
            names.each do |valid_name|
                @user.name = valid_name
                @user.should be_valid
            end      
        end
        after { @user.name = "Example User" }
    end    

    describe "when email is not present" do
        before { @user.email = " " }
        it { should_not be_valid }
        after { @user.email = "user@example.com" }
    end    
    describe "when name is too long" do
        before { @user.name = "a" * 300 }
        it { should_not be_valid }
        after { @user.name ="Example User" }
    end    
    describe "when name is too short" do
        before { @user.name = "aa" }
        it { should_not be_valid }
        after { @user.name ="Example User" }
    end    

    describe "when email format is invalid" do
        it "should be invalid" do
            addresses = %w[user@foo,com user_at_foo.org example.user@foo.]
            addresses.each do |invalid_address|
                @user.email = invalid_address
                @user.should_not be_valid
            end      
        end
        after { @user.email = "user@example.com" }
    end 

    describe "when email format is valid" do
        it "should be valid" do
            addresses = %w[user@foo.COM A_US-ER@f.b.org frst.lst@foo.jp a+b@baz.cn]
            addresses.each do |valid_address|
                @user.email = valid_address
                @user.should be_valid
            end      
        end
        after { @user.email = "user@example.com" }
    end    
    describe "when email address is already taken" do
        before do
            @user.name = "Example User"
            @user.email = "user@example.com"
            user_with_same_email = @user.dup
            user_with_same_email.email = @user.email.upcase            
            user_with_same_email.save
        end

        it { should_not be_valid }
        after { @user.email = "user1@example.com" }
    end    

    describe "return value of authenticate method" do
        before { @user.save }
        let(:found_user) { User.find_by_email(@user.email) }

        describe "with valid password" do
            it { should == found_user.authenticate(@user.password) }
        end

        describe "with invalid password" do
            let(:user_for_invalid_password) { found_user.authenticate("invalid") }

            it { should_not == user_for_invalid_password }
            specify { user_for_invalid_password.should be_false }
        end
    end    
    describe "remember token" do
    before { @user.save }
    its(:remember_token) { should_not be_blank }
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

