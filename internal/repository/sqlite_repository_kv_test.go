package repository

import (
	"os"
	"testing"
)

func TestSQLiteRepository_KeyValueStore(t *testing.T) {
	// Create a temporary database file
	tmpFile, err := os.CreateTemp("", "test_kv_*.sqlite")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	tmpPath := tmpFile.Name()
	tmpFile.Close()
	defer os.Remove(tmpPath)

	// Create repository
	repo, err := NewSQLiteRepository(tmpPath)
	if err != nil {
		t.Fatalf("Failed to create repository: %v", err)
	}
	defer repo.Close()

	t.Run("SetKeyValue and GetKeyValue", func(t *testing.T) {
		// Set a key-value pair
		err := repo.SetKeyValue("test_key", "test_value")
		if err != nil {
			t.Fatalf("SetKeyValue failed: %v", err)
		}

		// Get the value back
		value, exists, err := repo.GetKeyValue("test_key")
		if err != nil {
			t.Fatalf("GetKeyValue failed: %v", err)
		}
		if !exists {
			t.Error("Expected key to exist")
		}
		if value != "test_value" {
			t.Errorf("Expected 'test_value', got '%s'", value)
		}
	})

	t.Run("GetKeyValue for non-existent key", func(t *testing.T) {
		value, exists, err := repo.GetKeyValue("non_existent_key")
		if err != nil {
			t.Fatalf("GetKeyValue failed: %v", err)
		}
		if exists {
			t.Error("Expected key to not exist")
		}
		if value != "" {
			t.Errorf("Expected empty string, got '%s'", value)
		}
	})

	t.Run("SetKeyValue updates existing key", func(t *testing.T) {
		// Set initial value
		err := repo.SetKeyValue("update_key", "initial_value")
		if err != nil {
			t.Fatalf("SetKeyValue failed: %v", err)
		}

		// Update the value
		err = repo.SetKeyValue("update_key", "updated_value")
		if err != nil {
			t.Fatalf("SetKeyValue (update) failed: %v", err)
		}

		// Verify update
		value, exists, err := repo.GetKeyValue("update_key")
		if err != nil {
			t.Fatalf("GetKeyValue failed: %v", err)
		}
		if !exists {
			t.Error("Expected key to exist")
		}
		if value != "updated_value" {
			t.Errorf("Expected 'updated_value', got '%s'", value)
		}
	})

	t.Run("DeleteKeyValue", func(t *testing.T) {
		// Set a key first
		err := repo.SetKeyValue("delete_key", "to_be_deleted")
		if err != nil {
			t.Fatalf("SetKeyValue failed: %v", err)
		}

		// Delete it
		err = repo.DeleteKeyValue("delete_key")
		if err != nil {
			t.Fatalf("DeleteKeyValue failed: %v", err)
		}

		// Verify it's gone
		_, exists, err := repo.GetKeyValue("delete_key")
		if err != nil {
			t.Fatalf("GetKeyValue failed: %v", err)
		}
		if exists {
			t.Error("Expected key to not exist after deletion")
		}
	})

	t.Run("GetAllKeyValues", func(t *testing.T) {
		// Set multiple keys
		testData := map[string]string{
			"key1": "value1",
			"key2": "value2",
			"key3": "value3",
		}

		for k, v := range testData {
			err := repo.SetKeyValue(k, v)
			if err != nil {
				t.Fatalf("SetKeyValue failed for %s: %v", k, err)
			}
		}

		// Get all key-values
		allKV, err := repo.GetAllKeyValues()
		if err != nil {
			t.Fatalf("GetAllKeyValues failed: %v", err)
		}

		// Verify all test keys are present
		for k, v := range testData {
			if allKV[k] != v {
				t.Errorf("Expected allKV[%s] = '%s', got '%s'", k, v, allKV[k])
			}
		}
	})

	t.Run("SetKeyValue with empty key returns error", func(t *testing.T) {
		err := repo.SetKeyValue("", "value")
		if err == nil {
			t.Error("Expected error for empty key")
		}
	})

	t.Run("GetKeyValue with empty key returns error", func(t *testing.T) {
		_, _, err := repo.GetKeyValue("")
		if err == nil {
			t.Error("Expected error for empty key")
		}
	})

	t.Run("Version key storage", func(t *testing.T) {
		// This mimics the actual usage in main.go
		err := repo.SetKeyValue("version", "1.0.0")
		if err != nil {
			t.Fatalf("SetKeyValue for version failed: %v", err)
		}

		value, exists, err := repo.GetKeyValue("version")
		if err != nil {
			t.Fatalf("GetKeyValue for version failed: %v", err)
		}
		if !exists {
			t.Error("Expected version key to exist")
		}
		if value != "1.0.0" {
			t.Errorf("Expected version '1.0.0', got '%s'", value)
		}
	})
}
