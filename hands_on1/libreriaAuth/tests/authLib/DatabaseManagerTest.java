package authLib;

import static org.junit.Assert.*;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

public class DatabaseManagerTest {

    private DatabaseManager db;
    private final String MEMORY_DB_URL = "jdbc:sqlite:file:testdb?mode=memory&cache=shared";   
    private Connection keepAliveConnection;

    @Before
    public void setUp() throws SQLException {
        db = new DatabaseManager(MEMORY_DB_URL);
        keepAliveConnection = DriverManager.getConnection(MEMORY_DB_URL);

        String sql = "CREATE TABLE IF NOT EXISTS Utente ("
                + "Email TEXT PRIMARY KEY,"       
                + "Password TEXT NOT NULL," 
                + "Ruolo INTEGER NOT NULL,"       
                + "is_locked INTEGER DEFAULT 0" 
                + ");";

        try (Statement stmt = keepAliveConnection.createStatement()) {
            stmt.execute(sql);
        }
        
        String insertAdmin = "INSERT INTO Utente (Email, Password, Ruolo) VALUES ('admin@test.com', 'admin123', 1)";
        try (Statement stmt = keepAliveConnection.createStatement()) {
            stmt.execute(insertAdmin);
        }
    }

    @After
    public void tearDown() throws SQLException {
        if (keepAliveConnection != null && !keepAliveConnection.isClosed()) {
            keepAliveConnection.close();
        }
    }

    @Test
    public void testValidLogin() {
        User userAdmin = db.login("admin@test.com", "admin123");

        assertNotNull(userAdmin);
        assertEquals("admin@test.com", userAdmin.getUsername());
        assertTrue(userAdmin.isAdmin());
    }
}
