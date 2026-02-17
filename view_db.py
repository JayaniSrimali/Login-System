from app import app, db, User

def view_data():
    with app.app_context():
        users = User.query.all()
        print("\n" + "="*50)
        print("          CURRENT USERS IN DATABASE")
        print("="*50)
        print(f"{'ID':<5} | {'Username/Email':<30} | {'Provider':<10}")
        print("-" * 50)
        
        if not users:
            print("No users found in database.")
        else:
            for user in users:
                # Handle cases where email/phone is stored in different fields or fallback
                # Adjust based on your model; assuming email is primary for display
                display_name = user.email if user.email else user.phone
                provider = user.oauth_provider if user.oauth_provider else "Local"
                print(f"{user.id:<5} | {display_name:<30} | {provider:<10}")
        
        print("="*50 + "\n")

if __name__ == "__main__":
    view_data()
