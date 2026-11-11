import asyncio
import importlib.util
import unittest

LANGGRAPH_AVAILABLE = importlib.util.find_spec("langgraph") is not None


@unittest.skipUnless(LANGGRAPH_AVAILABLE, "optional langgraph dependency not installed")
class TestExcessiveAgencyAuditor(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        from core.agency_audit import ExcessiveAgencyAuditor
        self.auditor = ExcessiveAgencyAuditor()

    async def test_non_critical_action_allowed(self):
        result = await self.auditor.run_audit("get_user_profile", approved=False)
        self.assertFalse(result["is_critical"])
        self.assertNotIn("VIOLATION: Excessive Agency detected", result["audit_log"])
        self.assertTrue(any("Action authorized" in log for log in result["audit_log"]))

    async def test_critical_delete_action_violation(self):
        result = await self.auditor.run_audit("delete_all_records_from_s3", approved=False)
        self.assertTrue(result["is_critical"])
        self.assertTrue(any("VIOLATION" in log for log in result["audit_log"]))

    async def test_critical_admin_action_violation(self):
        result = await self.auditor.run_audit("grant_admin_privileges_to_user_123", approved=False)
        self.assertTrue(result["is_critical"])
        self.assertTrue(any("VIOLATION" in log for log in result["audit_log"]))

    async def test_critical_action_approved_by_human(self):
        result = await self.auditor.run_audit("delete_temporary_files", approved=True)
        self.assertTrue(result["is_critical"])
        self.assertFalse(any("VIOLATION" in log for log in result["audit_log"]))
        self.assertTrue(any("Action authorized" in log for log in result["audit_log"]))

    async def test_case_insensitivity_and_keywords(self):
        result_1 = await self.auditor.run_audit("ADMIN_shutdown", approved=False)
        result_2 = await self.auditor.run_audit("soft_delete_logs", approved=False)
        self.assertTrue(result_1["is_critical"])
        self.assertTrue(result_2["is_critical"])

    async def test_empty_action_handling(self):
        result = await self.auditor.run_audit("", approved=False)
        self.assertFalse(result["is_critical"])
        self.assertEqual(result.get("proposed_action"), "")


if __name__ == "__main__":
    unittest.main()
