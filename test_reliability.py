"""Focused regression tests for reliability and output-clarity fixes."""

import sys
import tempfile
import types
import unittest
from pathlib import Path
from subprocess import CompletedProcess, TimeoutExpired
from unittest.mock import patch

try:
    import requests  # noqa: F401
except ImportError:
    sys.modules["requests"] = types.ModuleType("requests")

from commands import executor
from commands.path_resolver import prepare_command_paths, resolve_folder_for_display
from commands.templates import get_command_tier, get_template
from commands.translator import _local_request, _network_diagnostic_request, translate
from db import database as db
from monitors import logins, startup
from query import engine
from query.sql_guard import SQLValidationError, validate as validate_sql


class ReliabilityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        db.init_db()

    def test_network_commands_are_routed_to_command_templates(self):
        expected = {
            "ping 127.0.0.1": "ping",
            "tracert 127.0.0.1": "tracert",
            "nslookup localhost": "nslookup",
            "netstat": "netstat",
            "ipconfig": "ipconfig",
        }
        for question, template_id in expected.items():
            with self.subTest(question=question):
                self.assertEqual(_network_diagnostic_request(question)["template_id"], template_id)
                translated = translate(question)
                self.assertTrue(translated["success"], translated["error"])
                self.assertEqual(translated["template_id"], template_id)

    def test_existing_command_tiers_and_sql_guard_remain_enforced(self):
        self.assertEqual(get_template("delete_directory")["tier"], "DESTRUCTIVE")
        self.assertEqual(get_template("create_directory")["tier"], "CREATE")
        self.assertEqual(get_template("create_file")["tier"], "CREATE")
        self.assertEqual(get_template("ping")["tier"], "SAFE")
        self.assertEqual(validate_sql("SELECT * FROM alerts"), "SELECT * FROM alerts")
        with self.assertRaises(SQLValidationError):
            validate_sql("DELETE FROM alerts")
        with self.assertRaises(SQLValidationError):
            validate_sql("SELECT * FROM monitor_state")

    def test_create_directory_and_file_run_as_create_and_are_verified(self):
        with tempfile.TemporaryDirectory(dir=Path.home()) as directory:
            target_dir = Path(directory) / "new multi word folder"
            target_file = Path(directory) / "notes.txt"
            with patch.object(db, "insert", return_value=1):
                folder_result = executor.execute(
                    "create_directory", "DESTRUCTIVE", {"path": str(target_dir)}, [],
                    f"mkdir {target_dir}", "create folder", confirmed=False,
                )
                file_result = executor.execute(
                    "create_file", "CREATE",
                    {"path": str(target_file), "content": "created by test"}, [],
                    f"create {target_file}", "create file", confirmed=False,
                )
            self.assertTrue(folder_result["success"])
            self.assertTrue(target_dir.is_dir())
            self.assertEqual(folder_result["created_path"], str(target_dir))
            self.assertTrue(file_result["success"])
            self.assertTrue(target_file.is_file())
            self.assertEqual(target_file.read_text(encoding="utf-8"), "created by test")

    def test_unquoted_multiword_folder_has_goal_metadata_without_execution(self):
        with tempfile.TemporaryDirectory(dir=Path.home()) as directory:
            result = translate(
                f'create the folder alpha beta in "{directory}"',
            )
            expected = str(Path(directory) / "alpha beta")
        self.assertTrue(result["success"], result.get("error"))
        self.assertEqual(result["template_id"], "create_directory")
        self.assertEqual(result["goal"], "create")
        self.assertEqual(result["target_phrase"], "alpha beta")
        self.assertEqual(result["target_type"], "folder")
        self.assertEqual(result["params"]["path"], expected)
        self.assertFalse(Path(expected).exists())

    def test_current_pc_battery_health_routes_to_local_battery_report(self):
        from query.llm import ask

        translated = translate("tell me current pc battery health")
        self.assertEqual(translated["template_id"], "battery_report")
        self.assertEqual(translated["goal"], "inspect")
        self.assertEqual(translated["target_phrase"], "battery")
        self.assertTrue(translated["interpretation"])

        with patch("commands.executor.execute") as execute:
            result = ask("tell me current pc battery health")
        self.assertEqual(result["source"], "command")
        self.assertEqual(result["command_data"]["template_id"], "battery_report")
        self.assertEqual(result["command_data"]["tier"], "SAFE")
        execute.assert_called_once()

    def test_python_file_in_folder_named_afterwards_needs_confirmation(self):
        from query.llm import handle_system_command

        with tempfile.TemporaryDirectory(dir=Path.home()) as directory:
            phrase = f"create a python file in '{directory}' named 'helo.py'"
            translated = translate(phrase)
            expected_path = str(Path(directory) / "helo.py")
            self.assertTrue(translated["success"], translated.get("error"))
            self.assertEqual(translated["template_id"], "create_file")
            self.assertEqual(translated["params"]["path"], expected_path)
            self.assertEqual(translated["goal"], "create")
            self.assertEqual(translated["target_phrase"], "helo.py")
            self.assertEqual(translated["target_type"], "file")
            self.assertIn("Create file 'helo.py'", translated["interpretation"])
            self.assertEqual(translated["tier"], "DESTRUCTIVE")
            self.assertFalse(Path(expected_path).exists())

            with patch("commands.executor.execute") as execute:
                response = handle_system_command(phrase)
            self.assertEqual(response["source"], "command_pending")
            self.assertEqual(response["command_data"]["tier"], "DESTRUCTIVE")
            execute.assert_not_called()

    def test_executable_file_creation_is_destructive(self):
        script_path = str(Path.home() / "Documents" / "test-script.ps1")
        self.assertEqual(get_command_tier("create_file", {"path": script_path}), "DESTRUCTIVE")
        with patch.object(db, "insert", return_value=1):
            result = executor.execute(
                "create_file", "CREATE",
                {"path": script_path, "content": "Write-Output test"}, [],
                f"create {script_path}", "create script", confirmed=False,
            )
        self.assertFalse(result["executed"])
        self.assertFalse(Path(script_path).exists())

    def test_python_script_file_tier_is_destructive(self):
        self.assertEqual(
            get_command_tier("create_file", {"path": r"C:\Users\me\Downloads\helo.py"}),
            "DESTRUCTIVE",
        )

    def test_create_path_checks_names_and_protected_locations(self):
        with tempfile.TemporaryDirectory(dir=Path.home()) as directory:
            reserved, reserved_error = prepare_command_paths(
                "create_file", {"path": str(Path(directory) / "NUL.txt"), "content": ""},
            )
            self.assertIn("reserved Windows", reserved_error)
        _, protected_error = prepare_command_paths(
            "create_directory", {"path": r"C:\Windows\Temp\cybersentinel-never-create"},
        )
        self.assertIn("protected location", protected_error)

    def test_copy_to_new_destination_is_create_and_never_overwrites(self):
        with tempfile.TemporaryDirectory(dir=Path.home()) as directory:
            source = Path(directory) / "source.txt"
            destination = Path(directory) / "copy.txt"
            source.write_text("source", encoding="utf-8")
            params = {"source": str(source), "dest": str(destination)}
            self.assertEqual(get_command_tier("copy_file", params), "CREATE")
            replace_request = {**params, "overwrite": True}
            self.assertEqual(get_command_tier("copy_file", replace_request), "CREATE")
            resolved, path_error = prepare_command_paths("copy_file", replace_request)
            self.assertIsNone(path_error)
            self.assertFalse(resolved["overwrite"])
            with patch.object(db, "insert", return_value=1):
                copied = executor.execute(
                    "copy_file", "DESTRUCTIVE", params, [], "copy", "copy file",
                )
            self.assertTrue(copied["success"])
            self.assertEqual(destination.read_text(encoding="utf-8"), "source")
            destination.write_text("do not overwrite", encoding="utf-8")
            _, error = prepare_command_paths("copy_file", params)
            self.assertIn("already exists", error)
            self.assertEqual(destination.read_text(encoding="utf-8"), "do not overwrite")

    def test_copy_create_uses_exclusive_destination_open(self):
        with tempfile.TemporaryDirectory(dir=Path.home()) as directory:
            source = Path(directory) / "source.txt"
            destination = Path(directory) / "destination.txt"
            source.write_text("source data", encoding="utf-8")
            original_open = Path.open

            def race_destination(path, mode="r", *args, **kwargs):
                if path == destination and mode == "xb":
                    with original_open(path, "x", encoding="utf-8") as created:
                        created.write("created by another process")
                return original_open(path, mode, *args, **kwargs)

            with patch.object(Path, "open", new=race_destination), \
                    patch.object(db, "insert", return_value=1):
                result = executor.execute(
                    "copy_file", "CREATE",
                    {"source": str(source), "dest": str(destination), "overwrite": False},
                    [], "copy source destination", "copy file", confirmed=True,
                )
            self.assertFalse(result["success"])
            self.assertEqual(
                destination.read_text(encoding="utf-8"),
                "created by another process",
            )

    def test_api_requires_confirmation_to_replace_existing_copy_target(self):
        from api.server import app

        with tempfile.TemporaryDirectory(dir=Path.home()) as directory:
            source = Path(directory) / "source.txt"
            destination = Path(directory) / "destination.txt"
            source.write_text("new data", encoding="utf-8")
            destination.write_text("keep this", encoding="utf-8")
            client = app.test_client()
            response = client.post(
                "/api/execute",
                json={
                    "confirmed": False,
                    "command_data": {
                        "template_id": "copy_file",
                        "params": {
                            "source": str(source),
                            "dest": str(destination),
                            "overwrite": True,
                        },
                        "command_parts": ["ignored"],
                        "display_command": "copy",
                    },
                },
            )
            self.assertEqual(response.status_code, 400)
            self.assertIn("DESTRUCTIVE", response.get_json()["error"])
            self.assertEqual(destination.read_text(encoding="utf-8"), "keep this")

    def test_command_error_text_overrides_zero_exit_code(self):
        process = CompletedProcess(
            args=["hostname"], returncode=0,
            stdout="The system cannot find the path specified.\n", stderr="",
        )
        with patch.object(executor.subprocess, "run", return_value=process), \
                patch.object(executor.db, "insert", return_value=1):
            result = executor.execute(
                "hostname", "SAFE", {}, [], "hostname", "test command",
            )
        self.assertFalse(result["success"])
        self.assertIn("cannot find the path specified", result["failure_reason"].lower())

    def test_timeout_preserves_partial_output_with_replacement_decoding(self):
        timeout = TimeoutExpired(
            "hostname", 1, output=b"partial \xff output", stderr=b"stderr \xfe",
        )
        with patch.object(executor.subprocess, "run", side_effect=timeout), \
                patch.object(executor.db, "insert", return_value=1):
            result = executor.execute(
                "hostname", "SAFE", {}, [], "hostname", "test timeout",
            )
        self.assertFalse(result["success"])
        self.assertIn("partial \ufffd output", result["stdout"])
        self.assertIn("stderr \ufffd", result["stderr"])

    def test_redirected_desktop_resolution_and_missing_path_hint(self):
        desktop = Path(resolve_folder_for_display("desktop"))
        self.assertTrue(desktop.is_dir(), desktop)
        with tempfile.TemporaryDirectory(dir=desktop) as parent_name:
            parent = Path(parent_name)
            (parent / "cybersentinel-validation-folder").mkdir()
            missing = str(parent / "cybersentinel-validation-folde")
            _, error = prepare_command_paths("list_directory", {"path": missing})
        self.assertIsNotNone(error)
        self.assertIn("Did you mean", error)

    def test_file_delete_phrasings_resolve_to_one_destructive_template(self):
        for question in (
            "delete temp.doc file on desktop",
            "delete file named 'temp.doc' on desktop",
            "remove a file called temp.doc from my desktop",
        ):
            with self.subTest(question=question):
                parsed = _local_request(question)
                self.assertEqual(parsed["template_id"], "delete_file")
                self.assertEqual(Path(parsed["params"]["path"]).name, "temp.doc")
        self.assertNotIn("/p", get_template("delete_file")["cmd"])

    def test_open_file_phrasings_resolve_to_the_launcher_template(self):
        path = r"C:\Users\dvsns\Documents\project notes.pdf"
        parsed = _local_request(f'open file "{path}"')
        self.assertEqual(parsed["template_id"], "open_file")
        self.assertEqual(parsed["params"]["path"], path)
        self.assertEqual(get_template("open_file")["tier"], "DESTRUCTIVE")
        with tempfile.TemporaryDirectory() as directory:
            file_path = Path(directory) / "project notes.pdf"
            file_path.write_text("test", encoding="utf-8")
            translated = translate(f'open file "{file_path}"')
        self.assertTrue(translated["success"], translated["error"])
        self.assertEqual(translated["template_id"], "open_file")

    def test_open_file_uses_default_app_only_after_confirmation(self):
        with tempfile.TemporaryDirectory() as directory:
            file_path = Path(directory) / "report.txt"
            file_path.write_text("test", encoding="utf-8")
            with patch.object(executor.os, "startfile", create=True) as startfile, \
                    patch.object(executor.db, "insert", return_value=1):
                blocked = executor.execute(
                    "open_file", "DESTRUCTIVE", {"path": str(file_path)}, [],
                    f"open {file_path}", "open test file",
                )
                self.assertFalse(blocked["executed"])
                startfile.assert_not_called()

                result = executor.execute(
                    "open_file", "DESTRUCTIVE", {"path": str(file_path)}, [],
                    f"open {file_path}", "open test file", confirmed=True,
                )
            self.assertTrue(result["success"])
            startfile.assert_called_once_with(str(file_path))

    def test_create_file_in_named_folder_on_desktop_resolves_nested_path(self):
        with tempfile.TemporaryDirectory() as directory:
            desktop = Path(directory)
            (desktop / "temp").mkdir()
            with patch("commands.translator.resolve_folder_for_display", return_value=str(desktop)):
                parsed = _local_request(
                    "create a file named 'tem.py' in temp folder on desktop"
                )
            resolved, error = prepare_command_paths("create_file", parsed["params"])
        self.assertIsNone(error)
        self.assertEqual(parsed["template_id"], "create_file")
        self.assertEqual(
            Path(resolved["path"]),
            desktop / "temp" / "tem.py",
        )

    def test_create_file_in_quoted_folder_under_downloads_resolves_existing_folder(self):
        with tempfile.TemporaryDirectory() as directory:
            downloads = Path(directory)
            (downloads / "hello").mkdir()
            with patch("commands.translator.resolve_folder_for_display", return_value=str(downloads)):
                result = translate(
                    "create a file named 'hi.py' in folder 'hello' in downloads"
                )

        self.assertTrue(result["success"], result.get("error"))
        self.assertEqual(result["template_id"], "create_file")
        self.assertEqual(
            Path(result["params"]["path"]),
            downloads / "hello" / "hi.py",
        )

    def test_local_file_delete_skips_llm_intent_classification(self):
        with patch.object(engine.llm, "handle_system_command", return_value={"source": "command_pending"}) as handler, \
                patch.object(engine.offline, "try_offline") as offline:
            result = engine.ask("delete temp.doc file on desktop")
        self.assertEqual(result["source"], "command_pending")
        handler.assert_called_once()
        offline.assert_not_called()

    def test_delete_file_uses_native_filesystem_operation(self):
        with tempfile.TemporaryDirectory() as directory:
            file_path = Path(directory) / "temp.doc"
            file_path.write_text("test", encoding="utf-8")
            with patch.object(executor.db, "insert", return_value=1):
                result = executor.execute(
                    "delete_file", "DESTRUCTIVE", {"path": str(file_path)}, [],
                    f"del {file_path}", "delete test file", confirmed=True,
                )
            self.assertTrue(result["success"])
            self.assertFalse(file_path.exists())

    def test_edge_autolaunch_guid_suffixes_share_a_display_name(self):
        self.assertEqual(
            startup.normalize_startup_name("MicrosoftEdgeAutoLaunch_0123456789abcdef"),
            "MicrosoftEdgeAutoLaunch",
        )

    def test_failed_login_event_fields_are_parsed(self):
        inserts = [""] * 21
        inserts[5] = "validation-user"
        inserts[8] = "5 - User32"
        inserts[10] = "10"
        inserts[18] = "C:\\Windows\\System32\\svchost.exe"
        inserts[19] = "192.0.2.25"
        event = types.SimpleNamespace(
            EventID=4625, StringInserts=inserts, RecordNumber=77,
        )
        parsed = logins._parse_event(event)
        self.assertEqual(parsed["event_id"], 4625)
        self.assertEqual(parsed["success"], 0)
        self.assertEqual(parsed["username"], "validation-user")
        self.assertEqual(parsed["logon_type"], 10)
        self.assertEqual(parsed["source_ip"], "192.0.2.25")

    def test_failed_login_events_are_inserted_into_login_history(self):
        inserts = [""] * 21
        inserts[5] = "validation-user"
        inserts[10] = "10"
        inserts[19] = "192.0.2.25"
        event = types.SimpleNamespace(EventID=4625, StringInserts=inserts, RecordNumber=77)
        event_log = types.SimpleNamespace(
            EVENTLOG_BACKWARDS_READ=1,
            EVENTLOG_SEQUENTIAL_READ=2,
            OpenEventLog=lambda _server, _name: object(),
            ReadEventLog=unittest.mock.Mock(side_effect=[[event], []]),
            CloseEventLog=unittest.mock.Mock(),
        )
        with patch.object(logins, "win32evtlog", event_log, create=True), \
                patch.object(logins, "_last_record_number", None), \
                patch.object(logins.db, "insert", return_value=1) as insert:
            logins._cycle()
        login_rows = [
            call.args[1] for call in insert.call_args_list
            if call.args[0] == "login_events"
        ]
        self.assertEqual(len(login_rows), 1)
        self.assertEqual(login_rows[0]["success"], 0)
        self.assertEqual(login_rows[0]["username"], "validation-user")

    def test_successful_login_uses_4624_source_ip_offset(self):
        inserts = [""] * 22
        inserts[5] = "validation-user"
        inserts[8] = "2"
        inserts[19] = "C:\\Windows\\System32\\winlogon.exe"
        inserts[20] = "192.0.2.25"
        event = types.SimpleNamespace(EventID=4624, StringInserts=inserts, RecordNumber=78)
        parsed = logins._parse_event(event)
        self.assertEqual(parsed["success"], 1)
        self.assertEqual(parsed["logon_type"], 2)
        self.assertEqual(parsed["source_ip"], "192.0.2.25")


if __name__ == "__main__":
    unittest.main()
