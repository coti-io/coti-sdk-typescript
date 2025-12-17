const fs = require('fs');
const path = require('path');
const { parseString } = require('xml2js');

function safeReadJSON(filePath) {
  try {
    if (!fs.existsSync(filePath)) return null;
    const raw = fs.readFileSync(filePath, 'utf8');
    return JSON.parse(raw);
  } catch (e) {
    console.error(`Failed to read JSON from ${filePath}:`, e.message);
    return null;
  }
}

function generateTestSummaryFromJUnit(xmlPath, cb) {
  if (!fs.existsSync(xmlPath)) {
    console.warn(`JUnit XML not found at ${xmlPath}`);
    cb(null, null);
    return;
  }

  const xml = fs.readFileSync(xmlPath, 'utf8');
  parseString(xml, (err, result) => {
    if (err) {
      console.error('Failed to parse JUnit XML:', err.message);
      cb(err);
      return;
    }

    const suites = result.testsuites?.testsuite || [];
    let summary = {
      totalTests: 0,
      totalFailures: 0,
      totalErrors: 0,
      totalTime: 0,
      suites: []
    };

    suites.forEach((suite) => {
      const attrs = suite.$ || {};
      const tests = parseInt(attrs.tests || 0, 10);
      const failures = parseInt(attrs.failures || 0, 10);
      const errors = parseInt(attrs.errors || 0, 10);
      const time = parseFloat(attrs.time || 0);

      summary.totalTests += tests;
      summary.totalFailures += failures;
      summary.totalErrors += errors;
      summary.totalTime += time;

      const testcases = suite.testcase || [];
      const cases = testcases.map((tc) => {
        const tca = tc.$ || {};
        const hasFailure = Array.isArray(tc.failure) && tc.failure.length > 0;
        const failureMessage = hasFailure ? (tc.failure[0]._ || tc.failure[0].$.message || '').toString().trim() : '';
        return {
          name: tca.name || 'Unnamed test',
          time: parseFloat(tca.time || 0),
          failed: hasFailure,
          failureMessage
        };
      });

      summary.suites.push({
        name: attrs.name || 'Unnamed suite',
        tests,
        failures,
        errors,
        time,
        cases
      });
    });

    cb(null, summary);
  });
}

function formatTestSummaryMarkdown(summary) {
  if (!summary) {
    return '## Test Results\n\nTest results not available.\n\n';
  }

  const passed = summary.totalTests - summary.totalFailures - summary.totalErrors;

  let md = '## Test Results Summary\n\n';
  md += '| Metric       | Value |\n';
  md += '| ------------ | ----- |\n';
  md += `| Total Tests  | ${summary.totalTests} |\n`;
  md += `| Passed       | ${passed} |\n`;
  md += `| Failed       | ${summary.totalFailures} |\n`;
  md += `| Errors       | ${summary.totalErrors} |\n`;
  md += `| Duration     | ${summary.totalTime.toFixed(2)}s |\n\n`;

  md += '---\n\n';
  md += '## Test Suites\n\n';

  if (summary.suites.length === 0) {
    md += 'No test suites found in JUnit report.\n\n';
    return md;
  }

  summary.suites.forEach((suite) => {
    md += `### ${suite.name}\n\n`;
    md += `- **Tests:** ${suite.tests}\n`;
    md += `- **Failures:** ${suite.failures}\n`;
    md += `- **Errors:** ${suite.errors}\n`;
    md += `- **Time:** ${suite.time}s\n\n`;

    suite.cases.forEach((tc) => {
      const status = tc.failed ? '❌' : '✅';
      md += `- ${status} ${tc.name}\n`;
      if (tc.failed && tc.failureMessage) {
        md += '\n';
        md += '  ```text\n';
        md += `  ${tc.failureMessage}\n`;
        md += '  ```\n';
      }
    });

    md += '\n---\n\n';
  });

  return md;
}

function formatCoverageMarkdown(coverage) {
  let md = '## Coverage Summary\n\n';

  if (!coverage || Object.keys(coverage).length === 0) {
    md += 'Coverage data not available.\n\n';
    return md;
  }

  md += '| File | Statements | Branches | Functions | Lines |\n';
  md += '| ---- | ---------- | -------- | --------- | ----- |\n';

  if (coverage.total) {
    const total = coverage.total;
    md += `| **All files** | ${total.statements.pct}% | ${total.branches.pct}% | ${total.functions.pct}% | ${total.lines.pct}% |\n`;
  }

  Object.keys(coverage)
    .filter((key) => key !== 'total')
    .sort()
    .forEach((file) => {
      const data = coverage[file];
      const fileName = path.basename(file);
      md += `| ${fileName} | ${data.statements.pct}% | ${data.branches.pct}% | ${data.functions.pct}% | ${data.lines.pct}% |\n`;
    });

  md += '\n';
  return md;
}

function generateMarkdownReport() {
  const projectRoot = path.join(__dirname, '..');
  const testsDir = path.join(projectRoot, 'tests');
  const outputPath = path.join(testsDir, 'README.md');

  const junitPath = process.env.JUNIT_XML_PATH || path.join(projectRoot, 'test-results.xml');
  const coveragePath =
    process.env.COVERAGE_SUMMARY_PATH || path.join(projectRoot, 'coverage', 'coverage-summary.json');

  if (!fs.existsSync(testsDir)) {
    console.error(`Tests directory not found at ${testsDir}`);
    process.exit(1);
  }

  console.log(`Using JUnit XML: ${junitPath}`);
  console.log(`Using coverage summary: ${coveragePath}`);

  generateTestSummaryFromJUnit(junitPath, (err, testSummary) => {
    if (err) {
      console.error('Error while generating test summary, continuing without test details.');
    }

    const coverage = safeReadJSON(coveragePath);

    let md = '# Test Report\n\n';
    md += `**Generated:** ${new Date().toISOString()}\n\n`;
    md += '---\n\n';

    md += formatTestSummaryMarkdown(testSummary);
    md += '\n';
    md += formatCoverageMarkdown(coverage);

    fs.writeFileSync(outputPath, md, 'utf8');
    console.log(`Markdown test report written to ${outputPath}`);
  });
}

generateMarkdownReport();


