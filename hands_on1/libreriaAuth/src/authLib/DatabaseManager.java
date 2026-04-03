package authLib;

import java.sql.*;

public class DatabaseManager {

    private final String DB_URL;
    
    public DatabaseManager(String DB_URL) {
		this.DB_URL = DB_URL;
	}

	public User login(String username, String password) {
        String sql = "SELECT password, ruolo, is_locked FROM Utente WHERE email = ?";

        try (Connection conn = DriverManager.getConnection(DB_URL);
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            
            pstmt.setString(1, username);
            ResultSet rs = pstmt.executeQuery();

            if (rs.next()) {
                if (rs.getInt("is_locked") == 1) {
                    System.out.println("Accesso negato: account bloccato.");
                    return null;
                }

                if (rs.getString("password").equals(password)) {
                    System.out.println("Login effettuato con successo. Benvenuto " + username);
                    return new User(username, rs.getBoolean("ruolo"));
                } else {
                    System.out.println("Password errata.");
                }
            } else {
                System.out.println("Utente non trovato.");
            }
        } catch (SQLException e) {
            System.err.println("Errore durante il login: " + e.getMessage());
        }
        return null; 
    }

    public boolean addUser(User currentUser, String newUsername, String newPassword, boolean newRole) {
        if (currentUser == null || !currentUser.isAdmin()) {
            System.out.println("ACCESSO NEGATO: Solo gli amministratori possono aggiungere utenti.");
            return false;
        }

        String sql = "INSERT INTO Utente(Email, Password, Ruolo) VALUES(?, ?, ?)";

        try (Connection conn = DriverManager.getConnection(DB_URL);
            PreparedStatement pstmt = conn.prepareStatement(sql)) {
            
            pstmt.setString(1, newUsername);
            pstmt.setString(2, newPassword); 
            pstmt.setInt(3, Boolean.compare(newRole, false));
            
            pstmt.executeUpdate();
            System.out.println("Operazione Admin: Utente '" + newUsername + "' creato con successo.");
            return true;
            
        } catch (SQLException e) {
            System.err.println("Impossibile creare l'utente. Conflitto sul nome? " + e.getMessage());
            return false;
        }
    }
}
