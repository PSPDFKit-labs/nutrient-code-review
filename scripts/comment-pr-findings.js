#!/usr/bin/env node

/**
 * Script to comment on PRs with code review findings from ClaudeCode
 */

const fs = require('fs');
const { spawnSync } = require('child_process');
const REVIEW_MARKER = '<!-- nutrient-code-review-action -->';

// PR Summary marker for identifying our summary sections
const PR_SUMMARY_MARKER = '📋 **PR Summary:**';

// Parse GitHub context from environment
const eventData = process.env.GITHUB_EVENT_PATH ? JSON.parse(fs.readFileSync(process.env.GITHUB_EVENT_PATH, 'utf8')) : {};
const context = {
  repo: {
    owner: process.env.GITHUB_REPOSITORY?.split('/')[0] || '',
    repo: process.env.GITHUB_REPOSITORY?.split('/')[1] || ''
  },
  issue: {
    number: parseInt(eventData.pull_request?.number || eventData.issue?.number || 0)
  },
  payload: {
    pull_request: {
      ...eventData.pull_request,
      head: {
        ...(eventData.pull_request?.head || {}),
        // Use PR_HEAD_SHA from environment if available (more reliable than event payload)
        sha: process.env.PR_HEAD_SHA || eventData.pull_request?.head?.sha || ''
      }
    }
  }
};

// GitHub API helper using gh CLI
function ghApi(endpoint, method = 'GET', data = null) {
  // Build arguments array safely to prevent command injection
  const args = ['api', endpoint, '--method', method];
  
  if (data) {
    args.push('--input', '-');
  }
  
  try {
    const result = spawnSync('gh', args, {
      encoding: 'utf8',
      input: data ? JSON.stringify(data) : undefined,
      stdio: ['pipe', 'pipe', 'pipe']
    });
    
    if (result.error) {
      throw new Error(`Failed to spawn gh process: ${result.error.message}`);
    }
    
    if (result.status !== 0) {
      console.error(`Error calling GitHub API: ${result.stderr}`);
      throw new Error(`gh process exited with code ${result.status}: ${result.stderr}`);
    }
    
    return JSON.parse(result.stdout);
  } catch (error) {
    console.error(`Error calling GitHub API: ${error.message}`);
    throw error;
  }
}

// Helper function to add reactions to a comment
function addReactionsToComment(commentId, isReviewComment = true) {
  const reactions = ['+1', '-1']; // thumbs up and thumbs down
  const endpoint = isReviewComment 
    ? `/repos/${context.repo.owner}/${context.repo.repo}/pulls/comments/${commentId}/reactions`
    : `/repos/${context.repo.owner}/${context.repo.repo}/issues/comments/${commentId}/reactions`;
  
  for (const reaction of reactions) {
    try {
      ghApi(endpoint, 'POST', { content: reaction });
      console.log(`Added ${reaction} reaction to comment ${commentId}`);
    } catch (error) {
      console.error(`Failed to add ${reaction} reaction to comment ${commentId}:`, error.message);
    }
  }
}

// Helper function to add reactions to all comments in a review
function addReactionsToReview(reviewId) {
  try {
    // Get all comments from the review
    const reviewComments = ghApi(`/repos/${context.repo.owner}/${context.repo.repo}/pulls/${context.issue.number}/reviews/${reviewId}/comments`);

    if (reviewComments && Array.isArray(reviewComments)) {
      for (const comment of reviewComments) {
        if (comment.id) {
          addReactionsToComment(comment.id, true);
        }
      }
    }
  } catch (error) {
    console.error(`Failed to get review comments for review ${reviewId}:`, error.message);
  }
}

// Check if a review was posted by this action
function isOwnReview(review) {
  if (!review.body) return false;
  if (review.body.includes(REVIEW_MARKER)) return true;

  // Check for our review summary patterns
  const ownPatterns = [
    PR_SUMMARY_MARKER,
    'No issues found. Changes look good.',
    /^Found \d+ .+ issues?\./,
    'Please address the high-severity issues before merging.',
    'Consider addressing the suggestions in the comments.',
    'Minor suggestions noted in comments.'
  ];

  for (const pattern of ownPatterns) {
    if (pattern instanceof RegExp) {
      if (pattern.test(review.body)) return true;
    } else {
      if (review.body.includes(pattern)) return true;
    }
  }

  return false;
}

// Find an existing review posted by this action
function findExistingReview() {
  try {
    const reviews = ghApi(`/repos/${context.repo.owner}/${context.repo.repo}/pulls/${context.issue.number}/reviews`);

    if (!reviews || !Array.isArray(reviews)) {
      return null;
    }

    for (const review of reviews) {
      const isDismissible = review.state === 'APPROVED' || review.state === 'CHANGES_REQUESTED';
      const isOwn = isOwnReview(review);
      const isBot = review.user && review.user.type === 'Bot';

      if (isBot && isDismissible && isOwn) {
        return review;
      }
    }

    return null;
  } catch (error) {
    console.error('Failed to find existing review:', error.message);
    return null;
  }
}

// Update an existing review's body (cannot change state via update)
function updateReviewBody(reviewId, newBody) {
  try {
    ghApi(
      `/repos/${context.repo.owner}/${context.repo.repo}/pulls/${context.issue.number}/reviews/${reviewId}`,
      'PUT',
      { body: newBody }
    );
    console.log(`Updated existing review ${reviewId}`);
    return true;
  } catch (error) {
    console.error(`Failed to update review ${reviewId}:`, error.message);
    return false;
  }
}

// Dismiss a specific review
function dismissReview(reviewId, message) {
  try {
    ghApi(
      `/repos/${context.repo.owner}/${context.repo.repo}/pulls/${context.issue.number}/reviews/${reviewId}/dismissals`,
      'PUT',
      { message }
    );
    console.log(`Dismissed review ${reviewId}: ${message}`);
    return true;
  } catch (error) {
    console.error(`Failed to dismiss review ${reviewId}:`, error.message);
    return false;
  }
}

// Format PR summary object into markdown
function formatPrSummary(prSummary, filesReviewed) {
  if (!prSummary || !prSummary.overview) return '';

  let result = `${PR_SUMMARY_MARKER}\n${prSummary.overview}\n\n`;

  if (prSummary.file_changes && prSummary.file_changes.length > 0) {
    // Build collapsible table with files_reviewed count
    const fileCount = filesReviewed || 0;
    result += `<details>\n<summary>${fileCount} file${fileCount === 1 ? '' : 's'} reviewed</summary>\n\n`;
    result += '| File | Changes |\n|------|---------|' + '\n';
    for (const fc of prSummary.file_changes) {
      // Use label for display (supports grouped files like "tests/*.py")
      const label = fc.label || (fc.files && fc.files[0]) || 'unknown';
      result += `| \`${label}\` | ${fc.changes} |\n`;
    }
    result += '\n</details>\n';
  }

  return result;
}

async function run() {
  try {
    // Read the findings
    let newFindings = [];
    try {
      const findingsData = fs.readFileSync('findings.json', 'utf8');
      newFindings = JSON.parse(findingsData);
    } catch (e) {
      console.log('Could not read findings file');
      return;
    }

    // Read the PR summary
    let prSummary = null;
    try {
      const summaryData = fs.readFileSync('pr-summary.json', 'utf8');
      prSummary = JSON.parse(summaryData);
    } catch (e) {
      console.log('Could not read PR summary file, continuing without it');
    }

    // Read the analysis summary (required - contains files_reviewed and severity counts)
    let analysisSummary;
    try {
      const analysisData = fs.readFileSync('analysis-summary.json', 'utf8');
      analysisSummary = JSON.parse(analysisData);
    } catch (e) {
      console.log('Could not read analysis summary file');
      return;
    }

    function buildReviewSummary(findings, prSummaryObj, analysisSummaryObj) {
      let body = '';

      // Add PR summary section if available
      const filesReviewed = analysisSummaryObj.files_reviewed || 0;
      const summaryText = formatPrSummary(prSummaryObj, filesReviewed);
      if (summaryText) {
        body += summaryText + '\n---\n\n';
      }

      const total = findings.length;

      if (total === 0) {
        body += 'No issues found. Changes look good.';
        return body;
      }

      // Build concise category summary
      const categories = {};
      for (const finding of findings) {
        const category = finding.category || 'other';
        if (!categories[category]) {
          categories[category] = [];
        }
        categories[category].push(finding);
      }

      const categoryNames = Object.keys(categories).map(c => c.toLowerCase());
      let issueTypes;
      if (categoryNames.length === 1) {
        issueTypes = categoryNames[0];
      } else if (categoryNames.length === 2) {
        issueTypes = categoryNames.join(' and ');
      } else {
        const last = categoryNames.pop();
        issueTypes = categoryNames.join(', ') + ', and ' + last;
      }

      // Build the findings summary
      body += `Found ${total} ${issueTypes} issue${total === 1 ? '' : 's'}. `;

      // Recommendation based on severity from analysis summary
      const high = analysisSummaryObj.high_severity || 0;
      const medium = analysisSummaryObj.medium_severity || 0;

      if (high > 0) {
        body += 'Please address the high-severity issues before merging.';
      } else if (medium > 0) {
        body += 'Consider addressing the suggestions in the comments.';
      } else {
        body += 'Minor suggestions noted in comments.';
      }

      return body;
    }

    const highSeverityCount = analysisSummary.high_severity || 0;
    const reviewEvent = highSeverityCount > 0 ? 'REQUEST_CHANGES' : 'APPROVE';
    const reviewBody = `${buildReviewSummary(newFindings, prSummary, analysisSummary)}\n\n${REVIEW_MARKER}`;

    // Prepare review comments
    const reviewComments = [];

    // Check if ClaudeCode comments should be silenced
    const silenceClaudeCodeComments = process.env.SILENCE_CLAUDECODE_COMMENTS === 'true';

    if (silenceClaudeCodeComments) {
      console.log(`ClaudeCode comments silenced - excluding ${newFindings.length} findings from inline comments`);
    }

    let fileMap = {};
    if (!silenceClaudeCodeComments && newFindings.length > 0) {
      // Get the PR diff to map file lines to diff positions
      const prFiles = ghApi(`/repos/${context.repo.owner}/${context.repo.repo}/pulls/${context.issue.number}/files?per_page=100`);

      // Create a map of file paths to their diff information
      fileMap = {};
      prFiles.forEach(file => {
        fileMap[file.filename] = file;
      });

      // Process findings synchronously (gh cli doesn't support async well)
      for (const finding of newFindings) {
        const file = finding.file;
        const line = finding.line || 1;
        const message = finding.description || 'Issue detected';
        const title = finding.title || message;
        const severity = finding.severity || 'HIGH';
        const category = finding.category || 'review_issue';

        // Check if this file is part of the PR diff
        if (!fileMap[file]) {
          console.log(`File ${file} not in PR diff, skipping`);
          continue;
        }

        // Build the comment body
        let commentBody = `🤖 **Code Review Finding: ${title}**\n\n`;
        commentBody += `**Severity:** ${severity}\n`;
        commentBody += `**Category:** ${category}\n`;

        // Add impact if available
        if (finding.impact) {
          commentBody += `\n**Impact:** ${finding.impact}\n`;
        }

        // Add recommendation if available
        if (finding.recommendation) {
          commentBody += `\n**Recommendation:** ${finding.recommendation}\n`;
        }

        // Add GitHub suggestion block if a code suggestion is available
        if (finding.suggestion) {
          commentBody += `\n\`\`\`suggestion\n${finding.suggestion}\n\`\`\`\n`;
        }

        // Prepare the review comment
        const reviewComment = {
          path: file,
          line: line,
          side: 'RIGHT',
          body: commentBody
        };

        // Handle multi-line suggestions by adding start_line
        const suggestionStartLine = finding.suggestion_start_line;
        const suggestionEndLine = finding.suggestion_end_line;

        if (finding.suggestion && suggestionStartLine && suggestionEndLine && suggestionStartLine !== suggestionEndLine) {
          // Multi-line suggestion: start_line is the first line, line is the last line
          reviewComment.start_line = suggestionStartLine;
          reviewComment.line = suggestionEndLine;
          reviewComment.start_side = 'RIGHT';
        }

        reviewComments.push(reviewComment);
      }
    }

    if (reviewComments.length === 0) {
      console.log('No inline comments to add; posting summary review only');
    }

    // Handle existing reviews - update in place if state unchanged, otherwise dismiss and recreate
    const existingReview = findExistingReview();
    const newState = highSeverityCount > 0 ? 'CHANGES_REQUESTED' : 'APPROVED';

    if (existingReview) {
      const existingState = existingReview.state;

      if (existingState === newState && reviewComments.length === 0) {
        // Same state and no new inline comments - update body in place
        const updated = updateReviewBody(existingReview.id, reviewBody);
        if (updated) {
          console.log(`Updated existing review in place (state: ${newState})`);
          return;
        }
        // If update failed, fall through to create new review
        console.log('Failed to update existing review, will create new one');
      } else {
        // State changed or has inline comments - dismiss old review and create new
        dismissReview(existingReview.id, `Re-reviewing: state changed from ${existingState} to ${newState}`);
      }
    }
    // If no existing review found, just create a new one (fall through to review creation below)

    try {
      // Create a review with all the comments
      const reviewData = {
        commit_id: context.payload.pull_request.head.sha,
        event: reviewEvent,
        body: reviewBody
      };
      if (reviewComments.length > 0) {
        reviewData.comments = reviewComments;
      }

      const reviewResponse = ghApi(`/repos/${context.repo.owner}/${context.repo.repo}/pulls/${context.issue.number}/reviews`, 'POST', reviewData);

      console.log(`Created review with ${reviewComments.length} inline comments`);
      
      // Add reactions to the comments
      if (reviewResponse && reviewResponse.id) {
        addReactionsToReview(reviewResponse.id);
      }
    } catch (error) {
      console.error('Error creating review:', error);
      
      // Fallback: try to create individual comments if review fails
      // This might happen if line numbers are outside the diff context
      console.log('Attempting fallback with adjusted line numbers...');
      
      for (const comment of reviewComments) {
        try {
          // Try to create comment with the original line
          const commentData = {
            path: comment.path,
            line: comment.line,
            side: comment.side,
            body: comment.body,
            commit_id: context.payload.pull_request.head.sha
          };
          
          const commentResponse = ghApi(`/repos/${context.repo.owner}/${context.repo.repo}/pulls/${context.issue.number}/comments`, 'POST', commentData);
          
          // Add reactions to the individual comment
          if (commentResponse && commentResponse.id) {
            addReactionsToComment(commentResponse.id, true);
          }
        } catch (lineError) {
          console.log(`Could not comment on ${comment.path}:${comment.line} - line might not be in diff context`);
          // If the specific line fails, try to get the file's patch and find a suitable line
          const fileInfo = fileMap[comment.path];
          if (fileInfo && fileInfo.patch) {
            // This is a simplified approach - in production you'd want more sophisticated line mapping
            console.log(`File ${comment.path} has additions but line ${comment.line} is not in the diff`);
          }
        }
      }
    }
  } catch (error) {
    console.error('Failed to comment on PR:', error);
    process.exit(1);
  }
}

run();
