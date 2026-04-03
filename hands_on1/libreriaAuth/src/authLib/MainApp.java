package authLib;

public class MainApp {
    public static void main(String[] args) {
        DatabaseManager db = new DatabaseManager("jdbc:sqlite:db/authlib.db");
        User userAdmin = db.login("mrossi@example.com", "password123");
        
        if (userAdmin != null) {
            db.addUser(userAdmin, "nuovo.user", "pass", false); 
        }

        System.out.println("---------------------------------");
   
    }
}
