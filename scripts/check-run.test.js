const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const {
  completionPayload,
  conclusionForJobStatus,
  run,
  startPayload,
} = require('./check-run');

test('startPayload creates an in-progress Check Run on the exact PR head', () => {
  const payload = startPayload({
    name: 'Nutrient Code Review',
    headSha: 'abc123',
    detailsUrl: 'https://github.com/PSPDFKit/PSPDFKit/actions/runs/42',
    requestedBy: 'pweiskircher',
    prNumber: '55889',
    now: new Date('2026-08-05T12:41:28Z'),
  });

  assert.deepEqual(payload, {
    name: 'Nutrient Code Review',
    head_sha: 'abc123',
    status: 'in_progress',
    started_at: '2026-08-05T12:41:28.000Z',
    details_url: 'https://github.com/PSPDFKit/PSPDFKit/actions/runs/42',
    output: {
      title: 'LLM review in progress',
      summary: 'Review of PR #55889 was requested by @pweiskircher.',
    },
  });
});

test('successful advisory reviews complete with a neutral conclusion', () => {
  assert.equal(conclusionForJobStatus('success'), 'neutral');
  assert.equal(conclusionForJobStatus('failure'), 'failure');
  assert.equal(conclusionForJobStatus('cancelled'), 'cancelled');

  const payload = completionPayload({
    status: 'success',
    detailsUrl: 'https://github.com/PSPDFKit/PSPDFKit/actions/runs/42',
    prNumber: '55889',
    now: new Date('2026-08-05T12:51:28Z'),
  });
  assert.equal(payload.status, 'completed');
  assert.equal(payload.conclusion, 'neutral');
  assert.equal(payload.output.title, 'LLM review completed');
});

test('run starts a Check Run and publishes its ID as an action output', async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'check-run-test-'));
  const outputPath = path.join(directory, 'output');
  const calls = [];
  const request = async (...args) => {
    calls.push(args);
    return { id: 9876 };
  };

  await run(
    {
      CHECK_RUN_OPERATION: 'start',
      CHECK_NAME: 'Nutrient Code Review',
      DETAILS_URL: 'https://example.test/run',
      GITHUB_OUTPUT: outputPath,
      GITHUB_REPOSITORY: 'PSPDFKit/PSPDFKit',
      GITHUB_TOKEN: 'token',
      PR_HEAD_SHA: 'abc123',
      PR_NUMBER: '55889',
      REQUESTED_BY: 'pweiskircher',
    },
    request,
  );

  assert.equal(calls.length, 1);
  assert.equal(calls[0][0], 'POST');
  assert.equal(calls[0][1], '/repos/PSPDFKit/PSPDFKit/check-runs');
  assert.match(fs.readFileSync(outputPath, 'utf8'), /check_run_id=9876/);
  fs.rmSync(directory, { recursive: true });
});

test('run completes the same Check Run with the job result', async () => {
  const calls = [];
  const request = async (...args) => {
    calls.push(args);
    return { id: 9876, conclusion: 'failure' };
  };

  await run(
    {
      CHECK_CONCLUSION: 'failure',
      CHECK_RUN_ID: '9876',
      CHECK_RUN_OPERATION: 'complete',
      DETAILS_URL: 'https://example.test/run',
      GITHUB_REPOSITORY: 'PSPDFKit/PSPDFKit',
      GITHUB_TOKEN: 'token',
      PR_NUMBER: '55889',
    },
    request,
  );

  assert.equal(calls[0][0], 'PATCH');
  assert.equal(calls[0][1], '/repos/PSPDFKit/PSPDFKit/check-runs/9876');
  assert.equal(calls[0][3].conclusion, 'failure');
});
