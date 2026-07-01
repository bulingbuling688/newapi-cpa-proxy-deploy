# Open this on Windows only when doing CPA Codex OAuth login.
# It intentionally uses local port 1457 so local 1455 remains free.
ssh -N -L 1457:127.0.0.1:1456 new
