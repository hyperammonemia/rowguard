'use strict';
const assert = require('assert/strict');
const fs = require('fs');
const path = require('path');
const { pathToFileURL } = require('url');
const { spawnSync } = require('child_process');
const { chromium } = require('playwright');

const root = path.resolve(__dirname, '..');
const output = path.join(root, 'output');
const scratch = path.join(root, '.qa', 'browser');
fs.mkdirSync(scratch, { recursive: true });
process.env.TMP = scratch;
process.env.TEMP = scratch;
const report = JSON.parse(fs.readFileSync(path.join(output, 'report.json'), 'utf8'));
const checks = [], errors = [], requests = [];
async function check(name, task) { await task(); checks.push({ name, passed: true }); console.log('PASS ' + name); }
function observe(page) {
  page.on('pageerror', error => errors.push(error.message));
  page.on('request', request => { if (/^https?:/.test(request.url())) requests.push(request.url()); });
}
async function exported(page, name) {
  const pending = page.waitForEvent('download');
  await page.click('#export-button');
  const download = await pending;
  assert.equal(download.suggestedFilename(), 'rowguard-filtered-preview.json');
  const file = path.join(scratch, name + '.json');
  await download.saveAs(file);
  return JSON.parse(fs.readFileSync(file, 'utf8'));
}
function fixture(value, name) {
  const source = path.join(scratch, name + '-report.json'), destination = path.join(scratch, name + '.html');
  fs.writeFileSync(source, JSON.stringify(value));
  const script = 'import json,sys; from pathlib import Path; from report import render_report; render_report(json.loads(Path(sys.argv[1]).read_text(encoding="utf-8")),Path(sys.argv[2]))';
  const run = spawnSync('python', ['-c', script, source, destination], { cwd: root, encoding: 'utf8' });
  assert.equal(run.status, 0, run.stdout + run.stderr);
  return pathToFileURL(destination).href;
}
function auditedFieldFixture(unique, name) {
  const directory = fs.mkdtempSync(path.join(scratch, name + '-'));
  const config = {
    rules: { version: 1, columns: { 'a + b': { required: true }, a: {}, b: {}, note: {} }, unique },
    rows: [['literal', 'left', 'right', 'line\nkeep'], ['literal', 'other', 'parts', 'second'], ['different', 'left', 'right', 'third'], ['', 'clean', 'unique', 'fourth']]
  };
  const input = path.join(directory, 'fixture.json');
  fs.writeFileSync(input, JSON.stringify(config));
  const script = [
    'import csv,json,sys',
    'from pathlib import Path',
    'from rowguard import audit,finalize_manifest',
    'from report import render_report',
    'source=Path(sys.argv[1]); root=source.parent; spec=json.loads(source.read_text(encoding="utf-8"))',
    '(root/"rules.json").write_text(json.dumps(spec["rules"]),encoding="utf-8")',
    'with (root/"input.csv").open("w",encoding="utf-8",newline="") as stream:',
    '    writer=csv.writer(stream); writer.writerow(list(spec["rules"]["columns"])); writer.writerows(spec["rows"])',
    'result=audit(root/"input.csv",root/"rules.json",root/"audit")',
    'render_report(result,root/"audit/index.html")',
    'finalize_manifest(root/"audit")'
  ].join('\n');
  const run = spawnSync('python', ['-c', script, input], { cwd: root, encoding: 'utf8' });
  assert.equal(run.status, 0, run.stdout + run.stderr);
  const audit = path.join(directory, 'audit');
  return {
    report: JSON.parse(fs.readFileSync(path.join(audit, 'report.json'), 'utf8')),
    issues: fs.readFileSync(path.join(audit, 'issues.jsonl'), 'utf8').trim().split('\n').map(line => JSON.parse(line)),
    url: pathToFileURL(path.join(audit, 'index.html')).href
  };
}
async function main() {
  const windowsChrome = 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe';
  const executablePath = process.env.BROWSER_PATH || (process.platform === 'win32' && fs.existsSync(windowsChrome) ? windowsChrome : undefined);
  const browser = await chromium.launch({ headless: true, executablePath });
  try {
    const page = await browser.newPage({ viewport: { width: 1440, height: 1080 }, acceptDownloads: true });
    observe(page);
    await page.goto(pathToFileURL(path.join(output, 'index.html')).href);
    const issueRows = page.locator('#issue-body tr[data-row]');
    await check('loads the actual audit totals, source hashes and synthetic demo label offline', async () => {
      assert.deepEqual(await page.locator('#report-data').evaluate(node => JSON.parse(node.textContent)), report);
      for (const [id, key] of [['rows-total', 'rows_total'], ['rows-clean', 'rows_clean'], ['rows-quarantined', 'rows_quarantined'], ['issues-total', 'issues_total']]) {
        assert.equal(Number((await page.locator('#' + id).textContent()).replaceAll(',', '')), report.summary[key]);
      }
      assert.equal(await issueRows.count(), report.issues_preview.length);
      assert.equal(await page.locator('#input-sha').textContent(), report.input.sha256);
      assert.equal(await page.locator('#rules-sha').textContent(), report.rules.sha256);
      assert.equal(await page.locator('#input-name').textContent(), report.input.name);
      assert.equal(await page.locator('#demo-note').isVisible(), report.demo?.synthetic === true);
      assert.match(await page.locator('#preview-limit').textContent(), new RegExp(String(report.preview_limit)));
      assert.equal(requests.length, 0);
    });
    await check('code filters match only loaded preview issues', async () => {
      for (const code of new Set(report.issues_preview.map(issue => issue.code))) {
        await page.selectOption('#code-filter', code);
        const expected = report.issues_preview.filter(issue => issue.code === code);
        assert.equal(await issueRows.count(), expected.length);
        assert.deepEqual(await issueRows.evaluateAll(rows => rows.map(row => row.dataset.code)), expected.map(issue => issue.code));
      }
      await page.click('#reset-button');
      assert.equal(await issueRows.count(), report.issues_preview.length);
    });
    await check('raw record details preserve source column order, values and physical line', async () => {
      const index = report.issues_preview.findIndex(issue => issue.code === 'duplicate');
      const issue = report.issues_preview[index];
      await page.locator('#issue-body .inspect-button').nth(index).click();
      assert.equal(await page.locator('#detail-heading').textContent(), `原始记录 #${issue.row}`);
      assert.match(await page.locator('.detail-position').textContent(), new RegExp(`CSV 起始物理行 ${issue.line}`));
      assert.deepEqual(await page.locator('.detail-fields dt').allTextContents(), report.columns);
      assert.deepEqual(await page.locator('.detail-fields pre').allTextContents(), report.columns.map(column => issue.data[column] === '' ? '（空字符串）' : issue.data[column]));
      assert.equal(await page.locator('.detail-message').textContent(), issue.message);
      assert.equal(await page.locator('#issue-body .inspect-button[aria-pressed="true"]').evaluate(node => node === document.activeElement), true);
    });
    await check('combined search and code filter download has explicit preview scope and original values', async () => {
      const duplicate = report.issues_preview.find(issue => issue.code === 'duplicate');
      await page.selectOption('#code-filter', 'duplicate');
      await page.fill('#issue-search', duplicate.value);
      const expected = report.issues_preview.filter(issue => issue.code === 'duplicate' && [issue.row, issue.line, issue.column, issue.code, issue.value, issue.message, ...Object.entries(issue.data).flat()].join('\n').toLowerCase().includes(duplicate.value.toLowerCase()));
      assert.equal(await issueRows.count(), expected.length);
      const payload = await exported(page, 'filtered-preview');
      assert.equal(payload.export_kind, 'rowguard.filtered_issue_preview');
      assert.deepEqual(payload.scope.filter, { code: 'duplicate', query: duplicate.value });
      assert.equal(payload.scope.issues_total, report.summary.issues_total);
      assert.equal(payload.scope.preview_loaded, report.issues_preview.length);
      assert.equal(payload.scope.issues_exported, expected.length);
      assert.equal(payload.scope.full_issues_file, 'issues.jsonl');
      assert.deepEqual(payload.summary, report.summary);
      assert.deepEqual(payload.issues_preview, expected);
      assert.deepEqual(payload.input, report.input);
      assert.deepEqual(payload.rules, report.rules);
      assert.deepEqual(payload.demo, report.demo);
    });
    await check('empty search exports an empty preview without changing full totals', async () => {
      await page.fill('#issue-search', 'NO_MATCH_ROWGUARD_90377');
      assert.equal(await issueRows.count(), 0);
      assert.match(await page.locator('#issue-body').textContent(), /没有匹配/);
      const payload = await exported(page, 'empty-preview');
      assert.deepEqual(payload.issues_preview, []);
      assert.equal(payload.scope.issues_exported, 0);
      assert.equal(payload.summary.rows_total, report.summary.rows_total);
      await page.click('#reset-button');
    });
    await check('result file links point to existing same-directory audit outputs', async () => {
      const hrefs = await page.locator('.file-link').evaluateAll(links => links.map(link => link.getAttribute('href')));
      assert.deepEqual(hrefs, ['clean.csv', 'quarantine.csv', 'issues.jsonl', 'manifest.json']);
      hrefs.forEach(name => assert.ok(fs.existsSync(path.join(output, name))));
    });
    await page.screenshot({ path: path.join(output, 'desktop-preview.png'), fullPage: true });
    await check('mobile layouts fit 390px and 320px with accessible filters and raw details', async () => {
      for (const width of [390, 320]) {
        await page.setViewportSize({ width, height: 1000 });
        const sizes = await page.evaluate(() => ({ scroll: document.documentElement.scrollWidth, client: document.documentElement.clientWidth }));
        assert.ok(sizes.scroll <= sizes.client, `Horizontal page overflow: ${JSON.stringify(sizes)}`);
        await page.selectOption('#code-filter', 'required');
        assert.equal(await issueRows.count(), report.issues_preview.filter(issue => issue.code === 'required').length);
        await page.locator('#issue-body .inspect-button').first().click();
        assert.match(await page.locator('#detail-heading').textContent(), /原始记录 #/);
        await page.click('#reset-button');
      }
      await page.setViewportSize({ width: 390, height: 1000 });
      await page.locator('.table-wrap').evaluate(container => { container.scrollLeft = 0; container.scrollTop = 0; });
      await page.screenshot({ path: path.join(output, 'mobile-preview.png'), fullPage: true });
    });
    const auxiliary = await browser.newPage({ acceptDownloads: true });
    observe(auxiliary);
    try {
      await check('untrusted CSV text remains literal in details, names, rules and exported JSON', async () => {
        const source = JSON.parse(JSON.stringify(report));
        const attack = '</script><img src=x onerror="window.injected=true"><script>window.injected=true</script> /*__REPORT__*/';
        source.input.name = attack;
        source.rules.definition.columns.note = { choices: [attack] };
        source.rules.source_text = JSON.stringify(source.rules.definition);
        source.issues_preview[0].message = attack;
        source.issues_preview[0].value = attack;
        source.issues_preview[0].data.note = '  001,"中文"\r\n' + attack + '\t0.000  ';
        await auxiliary.goto(fixture(source, 'untrusted-text'));
        assert.equal(await auxiliary.locator('#input-name').textContent(), attack);
        assert.equal(await auxiliary.locator('.detail-message').textContent(), attack);
        assert.ok((await auxiliary.locator('.detail-fields pre').allTextContents()).includes(source.issues_preview[0].data.note));
        assert.equal(await auxiliary.locator('img').count(), 0);
        assert.equal(await auxiliary.locator('script').count(), 2);
        assert.equal(await auxiliary.evaluate(() => window.injected), undefined);
        const payload = await exported(auxiliary, 'untrusted-preview');
        assert.deepEqual(payload.issues_preview, source.issues_preview);
        assert.deepEqual(payload.rules.definition, source.rules.definition);
      });
      await check('rule display and download preserve the original decimal text', async () => {
        const source = JSON.parse(JSON.stringify(report));
        source.rules.source_text = '{"version":1,"columns":{"amount":{"type":"number","max":1000000000000000.1234567890123456789}}}\n';
        source.rules.definition = JSON.parse(source.rules.source_text);
        await auxiliary.goto(fixture(source, 'precise-rules'));
        assert.equal(await auxiliary.locator('#rules-definition').textContent(), source.rules.source_text);
        const pending = auxiliary.waitForEvent('download');
        await auxiliary.click('#rules-export-button');
        const download = await pending;
        assert.equal(download.suggestedFilename(), 'rowguard-rules.json');
        const file = path.join(scratch, 'precise-rules-downloaded.json');
        await download.saveAs(file);
        assert.equal(fs.readFileSync(file, 'utf8'), source.rules.source_text);
        delete source.rules.source_text;
        await auxiliary.goto(fixture(source, 'rules-fallback'));
        assert.equal(await auxiliary.locator('#rules-export-button').isVisible(), false);
        assert.deepEqual(JSON.parse(await auxiliary.locator('#rules-definition').textContent()), source.rules.definition);
      });
      await check('truncated preview advertises its cap and never exports missing issues as complete', async () => {
        const source = JSON.parse(JSON.stringify(report));
        source.preview_limit = 2;
        source.issues_preview = source.issues_preview.slice(0, 2);
        await auxiliary.goto(fixture(source, 'truncated'));
        assert.match(await auxiliary.locator('#preview-count').textContent(), new RegExp(`2 / ${source.summary.issues_total}`));
        assert.match(await auxiliary.locator('#preview-limit').textContent(), /预览上限 2 条.*未包含全部问题/);
        const payload = await exported(auxiliary, 'truncated-preview');
        assert.equal(payload.scope.preview_truncated, true);
        assert.equal(payload.scope.preview_loaded, 2);
        assert.equal(payload.scope.issues_total, report.summary.issues_total);
        assert.equal(payload.issues_preview.length, 2);
      });
      await check('neutral clean reports and zero-preview reports do not invent issues or demo labels', async () => {
        const source = JSON.parse(JSON.stringify(report));
        delete source.demo;
        source.summary = { rows_total: 0, rows_clean: 0, rows_quarantined: 0, issues_total: 0, by_code: {} };
        source.issues_preview = [];
        await auxiliary.goto(fixture(source, 'clean-empty'));
        assert.equal(await auxiliary.locator('#demo-note').isVisible(), false);
        assert.match(await auxiliary.locator('#outcome').textContent(), /全部通过当前规则/);
        assert.equal((await exported(auxiliary, 'clean-empty-preview')).scope.issues_total, 0);
        source.summary = report.summary;
        source.preview_limit = 0;
        await auxiliary.goto(fixture(source, 'zero-preview'));
        assert.match(await auxiliary.locator('#outcome').textContent(), /存在隔离记录/);
        assert.match(await auxiliary.locator('#issue-body').textContent(), /未载入问题预览/);
        const payload = await exported(auxiliary, 'zero-preview-export');
        assert.equal(payload.scope.preview_truncated, true);
        assert.equal(payload.scope.preview_loaded, 0);
        assert.equal(payload.scope.issues_total, report.summary.issues_total);
      });
      const colliding = auditedFieldFixture([['a + b'], ['a', 'b']], 'colliding-fields');
      await check('actual audit keeps literal and composite fields distinct in details and full issues', async () => {
        const expected = [
          { row: 1, code: 'duplicate', fields: ['a + b'] },
          { row: 1, code: 'duplicate', fields: ['a', 'b'] },
          { row: 2, code: 'duplicate', fields: ['a + b'] },
          { row: 3, code: 'duplicate', fields: ['a', 'b'] },
          { row: 4, code: 'required', fields: ['a + b'] }
        ];
        const identities = issues => issues.map(({ row, code, fields }) => ({ row, code, fields }));
        assert.deepEqual(identities(colliding.report.issues_preview), expected);
        assert.deepEqual(identities(colliding.issues), expected);
        assert.deepEqual(new Set(colliding.issues.map(issue => issue.column)), new Set(['a + b']));
        await auxiliary.goto(colliding.url);
        for (let index = 0; index < expected.length; index++) {
          await auxiliary.locator('#issue-body .inspect-button').nth(index).click();
          assert.deepEqual(await auxiliary.locator('.detail-fields .affected dt').allTextContents(), expected[index].fields);
          assert.equal(await auxiliary.locator('.detail-field-note').count(), 0);
        }
        await auxiliary.locator('#issue-body .inspect-button').first().click();
        assert.deepEqual(await auxiliary.locator('.detail-fields pre').allTextContents(), ['literal', 'left', 'right', 'line\nkeep']);
      });
      await check('preview export preserves exact structured fields for colliding labels', async () => {
        await auxiliary.goto(colliding.url);
        const all = await exported(auxiliary, 'colliding-fields-all');
        assert.deepEqual(all.issues_preview, colliding.report.issues_preview);
        await auxiliary.selectOption('#code-filter', 'required');
        const filtered = await exported(auxiliary, 'literal-required-field');
        assert.equal(filtered.issues_preview.length, 1);
        assert.deepEqual(filtered.issues_preview[0].fields, ['a + b']);
        assert.equal(filtered.issues_preview[0].data['a + b'], '');
      });
      await check('legacy ambiguous duplicate labels show an explanation without guessing fields', async () => {
        const legacy = JSON.parse(JSON.stringify(colliding.report));
        legacy.issues_preview.forEach(issue => { delete issue.fields; });
        await auxiliary.goto(fixture(legacy, 'legacy-ambiguous-fields'));
        for (let index = 0; index < legacy.issues_preview.length; index++) {
          const issue = legacy.issues_preview[index];
          await auxiliary.locator('#issue-body .inspect-button').nth(index).click();
          if (issue.code === 'duplicate') {
            assert.deepEqual(await auxiliary.locator('.detail-fields .affected dt').allTextContents(), []);
            assert.match(await auxiliary.locator('.detail-field-note').textContent(), /旧版报告.*无法确定高亮字段/);
          } else {
            assert.deepEqual(await auxiliary.locator('.detail-fields .affected dt').allTextContents(), ['a + b']);
            assert.equal(await auxiliary.locator('.detail-field-note').count(), 0);
          }
        }
        assert.deepEqual((await exported(auxiliary, 'legacy-fields')).issues_preview, legacy.issues_preview);
      });
      await check('legacy unambiguous rules resolve both literal names and composite keys', async () => {
        for (const [name, fields] of [['literal', ['a + b']], ['composite', ['a', 'b']]]) {
          const original = auditedFieldFixture([fields], 'legacy-' + name);
          const legacy = JSON.parse(JSON.stringify(original.report));
          legacy.issues_preview.forEach(issue => { delete issue.fields; });
          await auxiliary.goto(fixture(legacy, 'legacy-' + name + '-fields'));
          for (let index = 0; index < legacy.issues_preview.length; index++) {
            const issue = legacy.issues_preview[index];
            await auxiliary.locator('#issue-body .inspect-button').nth(index).click();
            assert.deepEqual(await auxiliary.locator('.detail-fields .affected dt').allTextContents(), issue.code === 'duplicate' ? fields : ['a + b']);
            assert.equal(await auxiliary.locator('.detail-field-note').count(), 0);
          }
        }
      });
    } finally { await auxiliary.close(); }
    await check('all report interactions finish without script errors or external requests', async () => {
      assert.deepEqual(errors, []);
      assert.deepEqual(requests, []);
    });
    const record = { checked_at: new Date().toISOString(), browser: browser.version(), checks, page_errors: errors, external_requests: requests, screenshots: ['desktop-preview.png', 'mobile-preview.png'] };
    fs.writeFileSync(path.join(output, 'browser-validation.json'), JSON.stringify(record, null, 2) + '\n');
    console.log(`Completed ${checks.length} browser checks.`);
  } finally { await browser.close(); }
}
main().catch(error => { console.error(error); process.exitCode = 1; });
