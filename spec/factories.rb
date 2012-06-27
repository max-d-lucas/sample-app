FactoryGirl.define do
  factory :user do
    name     "Michael Hartl"
    email    "michael@example.com"
    password "Password1"
    password_confirmation "Password1"
  end
end
