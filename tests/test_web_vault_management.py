import pytest
import os
import shutil
from fastapi.testclient import TestClient
from web.api.app import create_app
from src.config import DEFAULT_DATA_DIR

@pytest.fixture
def client():
    app = create_app()
    with TestClient(app) as c:
        yield c

@pytest.fixture(autouse=True)
def setup_teardown_data():
    # Setup: ensure data dir exists
    os.makedirs(DEFAULT_DATA_DIR, exist_ok=True)
    
    # Backup existing vault.db if it exists
    backup_path = os.path.join(DEFAULT_DATA_DIR, "vault.db.bak")
    original_path = os.path.join(DEFAULT_DATA_DIR, "vault.db")
    has_backup = False
    if os.path.exists(original_path):
        shutil.copy2(original_path, backup_path)
        has_backup = True
    
    yield
    
    # Teardown: Clean up test vaults
    for f in os.listdir(DEFAULT_DATA_DIR):
        if f.startswith("test_") and f.endswith(".db"):
            try: os.remove(os.path.join(DEFAULT_DATA_DIR, f))
            except: pass
            
    # Restore original vault.db
    if has_backup:
        shutil.move(backup_path, original_path)
    elif os.path.exists(original_path):
        # If it didn't exist before but exists now (created by tests), remove it
        os.remove(original_path)


def test_list_vaults(client):
    # Create a dummy vault file
    test_vault = os.path.join(DEFAULT_DATA_DIR, "test_list.db")
    with open(test_vault, "w") as f:
        f.write("dummy")
    
    response = client.get("/api/vaults")
    assert response.status_code == 200
    data = response.json()
    assert any(v["name"] == "test_list.db" for v in data)


def test_create_vault(client):
    vault_name = "test_create.db"
    password = "extremely_secure_password_123"
    
    response = client.post("/api/vaults", json={"name": vault_name, "password": password})
    assert response.status_code == 200
    assert response.json()["status"] == "created"
    
    # Verify file exists
    assert os.path.exists(os.path.join(DEFAULT_DATA_DIR, vault_name))


def test_unlock_new_vault(client):
    vault_name = "test_unlock.db"
    password = "extremely_secure_password_123"
    
    # 1. Create
    client.post("/api/vaults", json={"name": vault_name, "password": password})
    
    # 2. Get CSRF token
    csrf_res = client.get("/api/csrf-token")
    csrf_token = csrf_res.json()["csrf_token"]
    
    # 3. Unlock
    response = client.post(
        "/api/unlock", 
        json={"password": password, "vault_name": vault_name},
        headers={"X-CSRF-Token": csrf_token}
    )
    assert response.status_code == 200
    assert response.json()["status"] == "unlocked"
    assert response.json()["vault_name"] == vault_name


def test_status_endpoint(client):
    # Create a vault
    vault_name = "test_status.db"
    with open(os.path.join(DEFAULT_DATA_DIR, vault_name), "w") as f:
        f.write("dummy")

    response = client.get("/api/status")
    assert response.status_code == 200
    data = response.json()
    assert data["locked"] is True
    assert data["vault_exists"] is True
    assert vault_name in data["available_vaults"]
