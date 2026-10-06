import unittest
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, patch

import backend
from fastapi.testclient import TestClient


class LabelGuardRuleTests(unittest.TestCase):
    def complete_fields(self, missing=()):
        examples = {
            "net_quantity": "500 g",
            "month_year": "Manufactured March 2026",
            "mrp": "₹ 120 inclusive of all taxes",
            "country_of_origin": "India",
            "consumer_care": "consumer@example.in, 1800-000-000",
        }
        return {
            rule["id"]: {
                "value": None if rule["id"] in missing else examples.get(rule["id"], f"Visible {rule['label']}"),
                "confidence": 0.95 if rule["id"] not in missing else 0.0,
            }
            for rule in backend.RULES
        }

    def test_complete_domestic_declarations_pass_and_conditional_field_is_n_a(self):
        results, violations = backend.run_rule_engine(self.complete_fields(), is_imported=False)
        self.assertEqual(violations, [])
        self.assertTrue(all(item["status"] == "pass" for item in results if item["field_id"] != "country_of_origin"))
        origin = next(item for item in results if item["field_id"] == "country_of_origin")
        self.assertEqual(origin["status"], "not_applicable")

    def test_missing_mandatory_declaration_produces_cited_violation(self):
        results, violations = backend.run_rule_engine(self.complete_fields({"mrp"}), is_imported=False)
        self.assertEqual(len(violations), 1)
        self.assertEqual(violations[0]["rule_id"], "LMPC Rule 6(1)(e)")
        self.assertIn("retail sale price", violations[0]["description"])
        mrp = next(item for item in results if item["field_id"] == "mrp")
        self.assertEqual(mrp["status"], "fail")

    def test_imported_country_origin_is_required(self):
        _, violations = backend.run_rule_engine(self.complete_fields({"country_of_origin"}), is_imported=True)
        self.assertTrue(any(item["rule_id"] == "LMPC Rule 6(8)" for item in violations))

    def test_malformed_quantity_and_price_fail_deterministic_checks(self):
        fields = self.complete_fields()
        fields["net_quantity"]["value"] = "A large amount"
        fields["mrp"]["value"] = "One hundred twenty"
        _, violations = backend.run_rule_engine(fields, is_imported=False)
        self.assertEqual({item["field"] for item in violations}, {"Net quantity", "Retail sale price (MRP)"})

    def test_uncertain_import_status_is_review_not_assumed_domestic(self):
        results, _ = backend.run_rule_engine(self.complete_fields(), is_imported=None)
        origin = next(item for item in results if item["field_id"] == "country_of_origin")
        self.assertEqual(origin["status"], "needs_review")

    def test_normalization_ignores_unconfigured_fields(self):
        raw = {
            "metadata": {"product_name": "Test package", "is_imported": False, "extra": "ignore"},
            "fields": {"generic_name": {"value": "Biscuits", "confidence": 0.9}, "extra": {"value": "ignore"}},
            "compliance_verdict": "pass",
        }
        name, imported, fields = backend.normalize_extraction(raw)
        self.assertEqual(name, "Test package")
        self.assertFalse(imported)
        self.assertEqual(set(fields), {item["id"] for item in backend.RULES})
        self.assertEqual(fields["generic_name"]["value"], "Biscuits")

    def test_seed_inspector_credential_is_bcrypt_hash(self):
        self.assertTrue(backend.bcrypt.checkpw(b"LabelGuardDemo!2026", backend.DEFAULT_INSPECTOR_PASSWORD_HASH.encode()))


class ScanEndpointTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.original_db_path = backend.DB_PATH
        backend.DB_PATH = Path(self.temp_dir.name) / "test.sqlite3"
        backend.initialize_database()
        self.initial_images = set(backend.UPLOAD_DIR.iterdir())
        self.client = TestClient(backend.app)

    def tearDown(self):
        self.client.close()
        for image in set(backend.UPLOAD_DIR.iterdir()) - self.initial_images:
            image.unlink(missing_ok=True)
        backend.DB_PATH = self.original_db_path
        self.temp_dir.cleanup()

    def upload_unreadable(self):
        null_fields = {rule["id"]: {"value": None, "confidence": 0} for rule in backend.RULES}
        response = self.client.post(
            "/api/scans",
            headers={"X-Session-ID": "61ddf38f-f71d-41c2-981f-295bc0145fac"},
            files={"file": ("label.png", b"\x89PNG\r\n\x1a\nfake", "image/png")},
        )
        return response, null_fields

    def test_unreadable_scan_is_stored_but_skips_rule_validation(self):
        with patch.object(backend, "extract_label", new=AsyncMock(return_value={"metadata": {}, "fields": {}})):
            response, _ = self.upload_unreadable()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["status"], "unreadable")
        self.assertEqual(response.json()["violations"], [])
        history = self.client.get("/api/history", params={"session_id": "61ddf38f-f71d-41c2-981f-295bc0145fac"})
        self.assertEqual(len(history.json()), 1)
        image = self.client.get(response.json()["image_url"], params={"session_id": "61ddf38f-f71d-41c2-981f-295bc0145fac"})
        self.assertEqual(image.status_code, 200)
        token = backend.issue_token("inspector")
        report = self.client.get(
            f"/api/inspector/scans/{response.json()['id']}/report.pdf",
            headers={"Authorization": f"Bearer {token}"},
        )
        self.assertEqual(report.status_code, 200)
        self.assertTrue(report.content.startswith(b"%PDF"))

    def test_extraction_error_is_not_saved(self):
        with patch.object(backend, "extract_label", new=AsyncMock(side_effect=RuntimeError("demo failure"))):
            response, _ = self.upload_unreadable()
        self.assertEqual(response.status_code, 502)
        self.assertIn("Something went wrong", response.json()["detail"])
        history = self.client.get("/api/history", params={"session_id": "61ddf38f-f71d-41c2-981f-295bc0145fac"})
        self.assertEqual(history.json(), [])

    def test_review_queue_requires_inspector_token(self):
        self.assertEqual(self.client.get("/api/inspector/pending").status_code, 401)
        token = backend.issue_token("inspector")
        self.assertEqual(self.client.get("/api/inspector/pending", headers={"Authorization": f"Bearer {token}"}).status_code, 200)


if __name__ == "__main__":
    unittest.main()
