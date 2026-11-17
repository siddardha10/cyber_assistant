"""Offline evaluation and policy tests for the general intent router."""

import unittest
from unittest.mock import patch

from commands import entity_resolver, intent_router, translator
from commands.templates import TEMPLATES
from evaluate_intents import build_evaluation_cases
from query import llm


class IntentRouterTests(unittest.TestCase):
    def test_evaluation_set_has_one_hundred_varied_cases(self):
        cases = build_evaluation_cases()
        self.assertGreaterEqual(len(cases), 100)
        self.assertTrue({"typo", "unquoted multi-word", "indirect", "follow-up", "underspecified"} <= {
            case["variant"] for case in cases
        })
        self.assertTrue({"DATA_QUERY", "OUT_OF_SCOPE", "CONVERSATIONAL"} <= {
            case["intent"] for case in cases
        })

    def test_every_action_has_retrieval_metadata(self):
        self.assertTrue(all(
            entry.get("description") and entry.get("example_phrasings")
            for entry in TEMPLATES.values()
        ))

    def test_open_application_uses_local_route_without_llm(self):
        resolved_application = {
            "status": "match",
            "match": {"name": "Notepad", "value": "notepad.exe"},
            "choices": [],
        }
        with patch.object(translator.config, "LLM_ENABLED", False), \
                patch.object(translator, "parse_goal") as parse_goal, \
                patch.object(translator, "resolve_entity", return_value=resolved_application):
            result = translator.translate("open notepad")

        self.assertTrue(result["success"], result.get("error"))
        self.assertEqual(result["template_id"], "start_application")
        self.assertEqual(result["params"]["name"], "notepad.exe")
        self.assertEqual(result["target_type"], "application")
        parse_goal.assert_not_called()

    def test_disappearing_service_is_skipped_during_live_inventory(self):
        import psutil

        class DisappearingService:
            def as_dict(self):
                raise FileNotFoundError("service disappeared")

        with patch.object(psutil, "win_service_iter", return_value=[DisappearingService()]):
            self.assertEqual(entity_resolver._live_candidates("service"), [])

    def test_retrieval_is_limited_to_five_and_finds_expected_action(self):
        with patch.object(intent_router, "_get_embeddings", return_value=None):
            intent_router._EMBEDDING_CACHE.clear()
            cases = build_evaluation_cases()
            for case in cases:
                if case["intent"] != "SYSTEM_COMMAND":
                    continue
                retrieved = intent_router.retrieve_actions(case["question"], 5)
                self.assertLessEqual(len(retrieved), 5)
                self.assertIn(
                    case["action_id"],
                    {candidate["action_id"] for candidate in retrieved},
                    case["question"],
                )

    def test_medium_confidence_safe_action_requires_yes_or_change(self):
        result = {
            "success": True,
            "template_id": "hostname",
            "tier": "SAFE",
            "params": {},
            "display_command": "hostname",
            "description": "Show the computer name",
            "command_parts": ["hostname"],
            "confidence": 0.7,
            "interpretation": "Show the local computer name.",
        }
        with patch("commands.translator.translate", return_value=result), \
                patch("commands.executor.execute") as execute:
            response = llm.handle_system_command("show my computer's name")
        self.assertEqual(response["source"], "command_review")
        self.assertIn("I understood", response["answer"])
        execute.assert_not_called()

    def test_out_of_scope_intent_survives_missing_goal_fields(self):
        with patch.object(llm.config, "LLM_ENABLED", True), \
                patch.object(
                    llm, "_call_llm",
                    return_value=(
                        '{"intent":"OUT_OF_SCOPE","confidence":0.94,'
                        '"goal":null,"target_phrase":[],"target_type":"unknown"}'
                    ),
                ):
            result = llm.ask("Write a poem about the moon")
        self.assertEqual(result["intent"], "OUT_OF_SCOPE")
        self.assertEqual(result["source"], "out_of_scope")

    def test_user_correction_is_remembered_for_the_original_phrase(self):
        remembered = {}
        parser_result = {
            "action_id": "start_application",
            "slots": {"name": "notepad"},
            "target_phrase": "notepad",
            "target_type": "application",
            "confidence": 0.9,
            "interpretation": "Launch Notepad.",
            "candidates": [],
        }

        def save_correction(phrase, action_id, target_type, target_phrase):
            remembered[phrase] = {
                "action_id": action_id,
                "target_type": target_type,
                "target_phrase": target_phrase,
            }

        def get_correction(phrase):
            return remembered.get(phrase)

        resolved_application = {
            "status": "match",
            "match": {"name": "Notepad", "value": "notepad.exe"},
            "choices": [],
        }
        with patch("commands.translator._local_request", return_value=None), \
                patch("commands.translator.parse_goal", return_value=parser_result) as parse_goal, \
                patch("commands.translator.resolve_entity", return_value=resolved_application), \
                patch("db.database.get_intent_correction", side_effect=get_correction), \
                patch("db.database.save_intent_correction", side_effect=save_correction):
            corrected = translator.translate(
                "Actually open notepad",
                [{"question": "start the editor"}],
            )
            repeated = translator.translate(
                "start the editor",
            )

        self.assertTrue(corrected["success"], corrected.get("error"))
        self.assertTrue(repeated["success"], repeated.get("error"))
        self.assertEqual(repeated["template_id"], "start_application")
        self.assertEqual(repeated["params"]["name"], "notepad.exe")
        self.assertIn("start the editor", remembered)
        self.assertEqual(parse_goal.call_count, 1)

    def test_generic_process_target_prompts_instead_of_guessing(self):
        parsed = {
            "action_id": "kill_process_by_name",
            "slots": {"name": "unsecapp.exe"},
            "target_phrase": "application",
            "confidence": 0.95,
            "interpretation": "Stop the application.",
            "candidates": [],
        }
        with patch.object(translator, "_local_request", return_value=None), \
                patch.object(translator, "parse_goal", return_value=parsed), \
                patch.object(translator, "get_entity_choices", return_value=[
                    {"name": "notepad.exe", "value": "notepad.exe"},
                ]), \
                patch.object(translator, "resolve_entity") as resolve:
            result = translator.translate("stop the app")
        self.assertFalse(result["success"])
        self.assertTrue(result["clarification"])
        self.assertEqual(result["error"], "Which process do you mean?")
        resolve.assert_not_called()

    def test_follow_up_process_uses_unique_recent_context_target(self):
        context_match = {
            "status": "match",
            "match": {
                "name": "notepad.exe",
                "value": "notepad.exe",
                "pid": 9876,
                "protected": False,
            },
            "choices": [],
        }
        with patch.object(translator, "_local_request", return_value=None), \
                patch.object(translator, "resolve_context_entity", return_value=context_match), \
                patch.object(translator, "resolve_entity") as resolve:
            result = translator.translate(
                "close it",
                [{"question": "is notepad running?", "answer": "Notepad is running."}],
            )
        self.assertTrue(result["success"], result.get("error"))
        self.assertEqual(result["template_id"], "kill_process_by_pid")
        self.assertEqual(result["params"], {"pid": "9876"})
        self.assertEqual(result["tier"], "DESTRUCTIVE")
        resolve.assert_not_called()

    def test_destructive_action_always_returns_confirmation(self):
        result = {
            "success": True,
            "template_id": "delete_file",
            "tier": "DESTRUCTIVE",
            "params": {"path": r"C:\Temp\example.txt"},
            "display_command": r"del /q C:\Temp\example.txt",
            "description": "Delete a file",
            "command_parts": ["cmd", "/c", "del", "/q", r"C:\Temp\example.txt"],
            "confidence": 0.2,
            "interpretation": "Delete the resolved file.",
        }
        with patch("commands.translator.translate", return_value=result), \
                patch("commands.executor.execute") as execute:
            response = llm.handle_system_command("remove it")
        self.assertEqual(response["source"], "command_pending")
        self.assertIn(r"C:\Temp\example.txt", response["answer"])
        execute.assert_not_called()

    def test_web_fallback_uses_only_fixed_queries(self):
        from query.web_fallback import get_search_query

        self.assertEqual(
            get_search_query("files"),
            "Windows file and folder management",
        )
        with self.assertRaises(ValueError):
            get_search_query("user-provided data")


if __name__ == "__main__":
    unittest.main()
