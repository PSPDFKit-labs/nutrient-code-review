"""Unit tests for the prompts module."""

from claudecode.prompts import get_unified_review_prompt


def _sample_pr_data():
    return {
        "number": 123,
        "title": "Add new feature",
        "body": "This PR adds a new feature to handle user input",
        "user": "testuser",
        "changed_files": 1,
        "additions": 10,
        "deletions": 5,
        "head": {
            "repo": {
                "full_name": "owner/repo"
            }
        },
        "files": [
            {
                "filename": "app.py",
                "status": "modified",
                "additions": 10,
                "deletions": 5,
            }
        ],
    }


class TestPrompts:
    """Test unified prompt generation."""

    def test_get_unified_review_prompt_basic(self):
        pr_data = _sample_pr_data()

        pr_diff = """
diff --git a/app.py b/app.py
@@ -1,5 +1,10 @@
 def process_input(user_input):
-    return user_input
+    # Process the input
+    result = eval(user_input)
+    return result
"""

        prompt = get_unified_review_prompt(pr_data, pr_diff)

        assert isinstance(prompt, str)
        assert len(prompt) > 0
        assert "123" in prompt
        assert "Add new feature" in prompt
        assert "testuser" in prompt
        assert "app.py" in prompt
        assert "eval(user_input)" in prompt
        assert "code quality" in prompt.lower()
        assert "security" in prompt.lower()

    def test_get_unified_review_prompt_without_diff_uses_file_reading_instructions(self):
        pr_data = _sample_pr_data()

        prompt = get_unified_review_prompt(pr_data, pr_diff="diff --git a/a b/a", include_diff=False)

        assert "PR DIFF CONTENT:" not in prompt
        assert "IMPORTANT - FILE READING INSTRUCTIONS:" in prompt

    def test_get_unified_review_prompt_no_files(self):
        pr_data = _sample_pr_data()
        pr_data["changed_files"] = 0
        pr_data["files"] = []

        prompt = get_unified_review_prompt(pr_data, pr_diff="")

        assert isinstance(prompt, str)
        assert "Files changed: 0" in prompt

    def test_get_unified_review_prompt_structure(self):
        pr_data = _sample_pr_data()
        pr_data["title"] = "Test PR"

        pr_diff = "diff --git a/test.py b/test.py\n+print('test')"
        prompt = get_unified_review_prompt(pr_data, pr_diff)

        assert "CONTEXT:" in prompt
        assert "OBJECTIVE:" in prompt
        assert "REQUIRED OUTPUT FORMAT:" in prompt
        assert pr_diff in prompt

    def test_get_unified_review_prompt_long_diff(self):
        pr_data = {
            "number": 12345,
            "title": "Major refactoring",
            "body": "Refactoring the entire codebase",
            "user": "refactor-bot",
            "changed_files": 10,
            "additions": 1000,
            "deletions": 500,
            "head": {
                "repo": {
                    "full_name": "owner/repo"
                }
            },
            "files": [
                {
                    "filename": f"file{i}.py",
                    "status": "modified",
                    "additions": 100,
                    "deletions": 50,
                }
                for i in range(10)
            ],
        }

        pr_diff = "\n".join([
            f"diff --git a/file{i}.py b/file{i}.py\n" +
            "\n".join([f"+line {j}" for j in range(50)])
            for i in range(10)
        ])

        prompt = get_unified_review_prompt(pr_data, pr_diff)

        assert isinstance(prompt, str)
        assert len(prompt) > 1000
        assert "12345" in prompt
        assert "Major refactoring" in prompt

    def test_get_unified_review_prompt_unicode(self):
        pr_data = {
            "number": 666,
            "title": "Add emoji support",
            "body": "This PR adds emoji rendering",
            "user": "emoji-user",
            "changed_files": 1,
            "additions": 42,
            "deletions": 0,
            "head": {
                "repo": {
                    "full_name": "owner/repo"
                }
            },
            "files": [
                {
                    "filename": "emoji.py",
                    "status": "added",
                    "additions": 42,
                    "deletions": 0,
                }
            ],
        }

        pr_diff = """
diff --git a/emoji.py b/emoji.py
+# Security check
+def check_input(text: str) -> bool:
+    return "ALERT" not in text
"""

        prompt = get_unified_review_prompt(pr_data, pr_diff)

        assert "emoji-user" in prompt
        assert "emoji.py" in prompt
        assert "ALERT" in prompt

    def test_get_unified_review_prompt_custom_instructions(self):
        pr_data = _sample_pr_data()

        prompt = get_unified_review_prompt(
            pr_data,
            pr_diff="diff --git a/app.py b/app.py",
            custom_review_instructions="Check transaction consistency.",
            custom_security_instructions="Check GraphQL authz.",
        )

        assert "Check transaction consistency." in prompt
        assert "Check GraphQL authz." in prompt

    def test_get_unified_review_prompt_includes_pr_summary_schema(self):
        """Test that prompt includes pr_summary in JSON schema."""
        pr_data = _sample_pr_data()
        prompt = get_unified_review_prompt(pr_data, pr_diff="diff")

        assert '"pr_summary"' in prompt
        assert '"overview"' in prompt
        assert '"file_changes"' in prompt
        assert '"label"' in prompt
        assert '"files"' in prompt

    def test_get_unified_review_prompt_includes_summary_guidelines(self):
        """Test that prompt includes PR summary guidelines."""
        pr_data = _sample_pr_data()
        prompt = get_unified_review_prompt(pr_data, pr_diff="diff")

        assert "PR SUMMARY GUIDELINES:" in prompt
        assert "2-4 sentences" in prompt
        assert "~10 words" in prompt