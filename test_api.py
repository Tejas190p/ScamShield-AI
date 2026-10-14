
import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

import api


class TestScamShieldAPI(unittest.TestCase):

    def setUp(self):
        # Create an isolated temporary database for each test.
        self.temp_dir = tempfile.TemporaryDirectory(
            prefix="scamshield_test_"
        )
        self.addCleanup(self.temp_dir.cleanup)

        self.db_path = str(
            Path(self.temp_dir.name) / "test_scans.db"
        )

        # Create the database table and close the connection properly.
        with closing(sqlite3.connect(self.db_path)) as connection:
            with connection:
                connection.execute("""
                    CREATE TABLE scans (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        scanned_at TEXT NOT NULL,
                        message TEXT NOT NULL,
                        risk_level TEXT NOT NULL,
                        risk_score INTEGER NOT NULL
                    )
                """)

        # Redirect API database operations to this test database.
        self.database_patcher = patch.object(
            api, "DATABASE_NAME", self.db_path
        )
        self.database_patcher.start()
        self.addCleanup(self.database_patcher.stop)

        # Mock AI so tests never call the real AI service.
        self.ai_patcher = patch.object(
            api,
            "analyze_with_ai",
            return_value="Mock AI analysis for automated testing.",
        )
        self.mock_ai = self.ai_patcher.start()
        self.addCleanup(self.ai_patcher.stop)

        # Create the test client and close it during cleanup.
        self.client = TestClient(api.app)
        self.addCleanup(self.client.close)

    def test_health_endpoint(self):
        response = self.client.get("/health")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["status"], "healthy")
        self.assertEqual(
            response.json()["database"], "connected"
        )

    def test_scan_returns_expected_response_fields(self):
        message = "Your package will arrive tomorrow."

        response = self.client.post(
            "/scan",
            json={"message": message},
        )

        self.assertEqual(response.status_code, 200)

        data = response.json()

        expected_fields = {
            "message",
            "final_risk_level",
            "risk_score",
            "category",
            "assessment",
            "warning_indicators",
            "ai_analysis",
            "recommended_action",
            "saved_to_history",
        }

        self.assertEqual(set(data.keys()), expected_fields)
        self.assertEqual(data["message"], message)
        self.assertTrue(data["saved_to_history"])
        self.assertEqual(
            data["ai_analysis"],
            "Mock AI analysis for automated testing.",
        )
        self.mock_ai.assert_called_once()

    def test_scan_saves_message_to_test_history(self):
        message = "Your package will arrive tomorrow."

        response = self.client.post(
            "/scan",
            json={"message": message},
        )

        self.assertEqual(response.status_code, 200)

        history = self.client.get("/history")

        self.assertEqual(history.status_code, 200)
        self.assertEqual(history.json()["count"], 1)
        self.assertEqual(
            history.json()["scans"][0]["message"],
            message,
        )

    def test_empty_message_is_rejected(self):
        response = self.client.post(
            "/scan",
            json={"message": ""},
        )

        self.assertEqual(response.status_code, 422)

    def test_whitespace_message_is_rejected(self):
        response = self.client.post(
            "/scan",
            json={"message": "   "},
        )

        self.assertEqual(response.status_code, 422)

    def test_missing_message_is_rejected(self):
        response = self.client.post("/scan", json={})

        self.assertEqual(response.status_code, 422)

    def test_history_limit_validation(self):
        for limit in (0, 101):
            with self.subTest(limit=limit):
                response = self.client.get(
                    "/history",
                    params={"limit": limit},
                )

                self.assertEqual(response.status_code, 422)

    def test_empty_history(self):
        response = self.client.get("/history")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["count"], 0)
        self.assertEqual(response.json()["scans"], [])

    def test_empty_stats(self):
        response = self.client.get("/stats")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["total_scans"], 0)
        self.assertEqual(response.json()["high_risk_scans"], 0)

    def test_stats_update_after_scan(self):
        response = self.client.post(
            "/scan",
            json={
                "message": "Your package will arrive tomorrow."
            },
        )

        self.assertEqual(response.status_code, 200)

        stats = self.client.get("/stats")

        self.assertEqual(stats.status_code, 200)
        self.assertEqual(stats.json()["total_scans"], 1)

    def test_scan_does_not_call_live_ai(self):
        response = self.client.post(
            "/scan",
            json={
                "message": "Your package will arrive tomorrow."
            },
        )

        self.assertEqual(response.status_code, 200)
        self.mock_ai.assert_called_once()


if __name__ == "__main__":
    unittest.main(verbosity=2)
