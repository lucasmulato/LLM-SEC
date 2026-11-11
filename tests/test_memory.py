import tempfile
import unittest
from pathlib import Path
from core.memory import CampaignMemory


class TestCampaignMemory(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test_campaign.db"
        self.memory = CampaignMemory(db_path=self.db_path)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_init_creates_table(self):
        self.assertTrue(self.db_path.exists())
        with self.memory._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='attacks'")
            self.assertIsNotNone(cursor.fetchone())

    def test_log_and_retrieve_success(self):
        self.memory.log_attempt(
            goal="jailbreak model",
            payload="ignore previous instructions",
            success=True,
            response="I cannot comply"
        )
        self.memory.log_attempt(
            goal="normal query",
            payload="hello world",
            success=False,
            response="hello"
        )
        payloads = self.memory.get_successful_payloads()
        self.assertEqual(payloads, ["ignore previous instructions"])

    def test_filter_by_keyword(self):
        self.memory.log_attempt("leak system prompt", "p1", True, "r1")
        self.memory.log_attempt("extract weights", "p2", True, "r2")
        self.memory.log_attempt("leak api key", "p3", True, "r3")

        leak_payloads = self.memory.get_successful_payloads(goal_keyword="leak")
        self.assertEqual(len(leak_payloads), 2)
        self.assertIn("p1", leak_payloads)
        self.assertIn("p3", leak_payloads)

    def test_like_wildcard_escaping(self):
        # Insert a goal with literal 100% and another without
        self.memory.log_attempt("achieve 100% bypass", "p_wildcard", True, "r1")
        self.memory.log_attempt("achieve 1000 bypass", "p_non_wildcard", True, "r2")

        # Searching for literal "100%" must NOT match "1000 bypass"
        payloads = self.memory.get_successful_payloads(goal_keyword="100%")
        self.assertEqual(payloads, ["p_wildcard"])


if __name__ == "__main__":
    unittest.main()
