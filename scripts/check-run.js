#!/usr/bin/env node

const fs = require('fs');
const https = require('https');

const API_VERSION = '2022-11-28';

function requestJson(method, path, token, body, requestImpl = https.request) {
  return new Promise((resolve, reject) => {
    const payload = body === undefined ? '' : JSON.stringify(body);
    const request = requestImpl(
      {
        hostname: 'api.github.com',
        method,
        path,
        headers: {
          Accept: 'application/vnd.github+json',
          Authorization: `Bearer ${token}`,
          'User-Agent': 'nutrient-code-review',
          'X-GitHub-Api-Version': API_VERSION,
          ...(payload ? { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload) } : {}),
        },
      },
      (response) => {
        let responseBody = '';
        response.setEncoding('utf8');
        response.on('data', (chunk) => {
          responseBody += chunk;
        });
        response.on('end', () => {
          let parsed = {};
          if (responseBody) {
            try {
              parsed = JSON.parse(responseBody);
            } catch (error) {
              reject(new Error(`GitHub returned invalid JSON (${response.statusCode}): ${error.message}`));
              return;
            }
          }

          if (response.statusCode < 200 || response.statusCode >= 300) {
            reject(new Error(`GitHub API ${method} ${path} failed (${response.statusCode}): ${parsed.message || responseBody}`));
            return;
          }

          resolve(parsed);
        });
      },
    );

    request.on('error', reject);
    if (payload) request.write(payload);
    request.end();
  });
}

function appendOutput(name, value, outputPath = process.env.GITHUB_OUTPUT) {
  if (!outputPath) return;
  fs.appendFileSync(outputPath, `${name}=${value}\n`);
}

function conclusionForJobStatus(status) {
  switch (status) {
    case 'failure':
      return 'failure';
    case 'cancelled':
      return 'cancelled';
    case 'success':
    default:
      // This reviewer is advisory and must not become an approval gate.
      return 'neutral';
  }
}

function startPayload({ name, headSha, detailsUrl, requestedBy, prNumber, now = new Date() }) {
  return {
    name,
    head_sha: headSha,
    status: 'in_progress',
    started_at: now.toISOString(),
    details_url: detailsUrl,
    output: {
      title: 'LLM review in progress',
      summary: `Review of PR #${prNumber} was requested by @${requestedBy}.`,
    },
  };
}

function completionPayload({ status, detailsUrl, prNumber, now = new Date() }) {
  const conclusion = conclusionForJobStatus(status);
  const succeeded = conclusion === 'neutral';
  return {
    status: 'completed',
    conclusion,
    completed_at: now.toISOString(),
    details_url: detailsUrl,
    output: {
      title: succeeded ? 'LLM review completed' : `LLM review ${conclusion}`,
      summary: succeeded
        ? `Review of PR #${prNumber} completed. See the PR review and workflow details.`
        : `Review of PR #${prNumber} did not complete successfully. Open the workflow details for the failure.`,
    },
  };
}

async function run(env = process.env, request = requestJson) {
  const operation = env.CHECK_RUN_OPERATION;
  const repository = env.GITHUB_REPOSITORY;
  const token = env.GITHUB_TOKEN;

  if (!repository || !token) throw new Error('GITHUB_REPOSITORY and GITHUB_TOKEN are required');

  if (operation === 'start') {
    appendOutput('check_run_id', '', env.GITHUB_OUTPUT);
    if (!env.PR_HEAD_SHA) throw new Error('PR_HEAD_SHA is required to start a Check Run');

    const result = await request(
      'POST',
      `/repos/${repository}/check-runs`,
      token,
      startPayload({
        name: env.CHECK_NAME || 'Nutrient Code Review',
        headSha: env.PR_HEAD_SHA,
        detailsUrl: env.DETAILS_URL,
        requestedBy: env.REQUESTED_BY || 'unknown',
        prNumber: env.PR_NUMBER,
      }),
    );
    appendOutput('check_run_id', result.id, env.GITHUB_OUTPUT);
    console.log(`Created Check Run ${result.id} on ${env.PR_HEAD_SHA}`);
    return result;
  }

  if (operation === 'complete') {
    if (!env.CHECK_RUN_ID) throw new Error('CHECK_RUN_ID is required to complete a Check Run');
    const result = await request(
      'PATCH',
      `/repos/${repository}/check-runs/${env.CHECK_RUN_ID}`,
      token,
      completionPayload({
        status: env.CHECK_CONCLUSION,
        detailsUrl: env.DETAILS_URL,
        prNumber: env.PR_NUMBER,
      }),
    );
    console.log(`Completed Check Run ${env.CHECK_RUN_ID} with ${result.conclusion || conclusionForJobStatus(env.CHECK_CONCLUSION)}`);
    return result;
  }

  throw new Error(`Unsupported CHECK_RUN_OPERATION: ${operation}`);
}

if (require.main === module) {
  run().catch((error) => {
    // Check publishing is observability. It must not prevent the review itself.
    console.log(`::warning::${error.message}`);
    process.exitCode = 0;
  });
}

module.exports = {
  appendOutput,
  completionPayload,
  conclusionForJobStatus,
  requestJson,
  run,
  startPayload,
};
