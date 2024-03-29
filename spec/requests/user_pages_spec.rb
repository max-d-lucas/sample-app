require 'spec_helper'

describe "User pages" do

    subject { page }

    describe "signup" do
        before { visit signup_path }
        let(:submit) { "Create my account" }
 
        describe "with invalid information" do
            it "should not create a user" do
                expect { click_button submit }.not_to change(User, :count)
            end
        end
    end

    describe "with valid information" do
        before do
            visit signup_path
            fill_in "Name",     with: "Example User2"
            fill_in "Email",        with: "user2@example.com"
            fill_in "Password",     with: "Password2"
            fill_in "Confirmation", with: "Password2"
        end

        it "should create a user" do
            expect { click_button submit }.to change(User, :count).by(1)
        end
        describe "after saving the user" do
            it { should have_link('Sign out') }
        end        
    end

    describe "profile page" do
        let(:user) { FactoryGirl.create(:user) }
        before { visit user_path(user) }

        it { should have_selector('h1',    text: user.name) }
        it { should have_selector('title', text: user.name) }
    end  
end
