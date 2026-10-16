"""Tests for repository guidelines and instruction files loaded from the checkout."""

import os

from claudecode.github_action_audit import load_instructions_file, load_repository_guidelines
from claudecode.prompts import get_unified_review_prompt


def _pr_data():
    return {
        'number': 1, 'title': 'T', 'body': '', 'user': 'u', 'changed_files': 1,
        'additions': 1, 'deletions': 0, 'head': {'repo': {'full_name': 'o/r'}},
        'files': [{'filename': 'src/app/main.py'}],
    }


class TestLoadRepositoryGuidelines:
    def test_loads_root_dotclaude_and_changed_file_directories(self, tmp_path):
        (tmp_path / 'CLAUDE.md').write_text('root rules')
        (tmp_path / '.claude').mkdir()
        (tmp_path / '.claude' / 'CLAUDE.md').write_text('dot claude rules')
        (tmp_path / 'src' / 'app').mkdir(parents=True)
        (tmp_path / 'src' / 'CLAUDE.md').write_text('src rules')
        (tmp_path / 'src' / 'app' / 'CLAUDE.md').write_text('app rules')
        (tmp_path / 'other').mkdir()
        (tmp_path / 'other' / 'CLAUDE.md').write_text('unrelated rules')

        result = load_repository_guidelines(tmp_path, ['src/app/main.py'])

        assert result.index('root rules') < result.index('dot claude rules') < result.index('src rules') < result.index('app rules')
        assert '--- src/app/CLAUDE.md ---' in result
        assert 'unrelated rules' not in result

    def test_returns_none_without_guideline_files(self, tmp_path):
        assert load_repository_guidelines(tmp_path, ['a.py']) is None

    def test_ignores_symlinks_out_of_the_checkout(self, tmp_path):
        repo = tmp_path / 'repo'
        repo.mkdir()
        secret = tmp_path / 'secret.txt'
        secret.write_text('ANTHROPIC_API_KEY=sk-test')
        os.symlink(secret, repo / 'CLAUDE.md')
        (repo / 'linked').symlink_to(tmp_path, target_is_directory=True)

        assert load_repository_guidelines(repo, ['linked/secret.txt']) is None

    def test_truncates_large_files_and_caps_total(self, tmp_path):
        (tmp_path / 'CLAUDE.md').write_text('a' * 30000)
        for name in ('x', 'y', 'z'):
            (tmp_path / name).mkdir()
            (tmp_path / name / 'CLAUDE.md').write_text(name * 20000)

        result = load_repository_guidelines(tmp_path, ['x/f', 'y/f', 'z/f'])

        assert '(truncated)' in result
        assert '--- x/CLAUDE.md ---' in result
        assert '--- z/CLAUDE.md ---' not in result


class TestLoadInstructionsFile:
    def test_resolves_relative_paths_against_checkout(self, tmp_path, monkeypatch):
        (tmp_path / '.github').mkdir()
        (tmp_path / '.github' / 'review.txt').write_text('custom rules')
        monkeypatch.chdir(tmp_path.parent)
        monkeypatch.setenv('REPO_PATH', str(tmp_path))
        monkeypatch.setenv('CUSTOM_REVIEW_INSTRUCTIONS', '.github/review.txt')

        assert load_instructions_file('CUSTOM_REVIEW_INSTRUCTIONS', 'review') == 'custom rules'

    def test_accepts_absolute_paths(self, tmp_path, monkeypatch):
        path = tmp_path / 'abs.txt'
        path.write_text('absolute rules')
        monkeypatch.setenv('CUSTOM_REVIEW_INSTRUCTIONS', str(path))

        monkeypatch.setenv('REPO_PATH', str(tmp_path / 'repo'))

        assert load_instructions_file('CUSTOM_REVIEW_INSTRUCTIONS', 'review') == 'absolute rules'

    def test_missing_file_returns_none(self, tmp_path, monkeypatch):
        monkeypatch.setenv('REPO_PATH', str(tmp_path))
        monkeypatch.setenv('CUSTOM_REVIEW_INSTRUCTIONS', 'missing.txt')
        assert load_instructions_file('CUSTOM_REVIEW_INSTRUCTIONS', 'review') is None

    def test_unset_returns_none(self, tmp_path, monkeypatch):
        monkeypatch.delenv('CUSTOM_REVIEW_INSTRUCTIONS', raising=False)
        assert load_instructions_file('CUSTOM_REVIEW_INSTRUCTIONS', 'review') is None


class TestPromptGuidelinesSection:
    def test_includes_guidelines_when_present(self):
        prompt = get_unified_review_prompt(_pr_data(), repository_guidelines='--- CLAUDE.md ---\nUse tabs')
        assert 'REPOSITORY GUIDELINES:' in prompt
        assert 'Use tabs' in prompt

    def test_omits_section_without_guidelines(self):
        assert 'REPOSITORY GUIDELINES:' not in get_unified_review_prompt(_pr_data())
