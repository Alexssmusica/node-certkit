const { execSync } = require('child_process');
const fs = require('fs');
const semver = require('semver');

async function main() {
  const packageJson = JSON.parse(fs.readFileSync('package.json', 'utf8'));
  const releaserc = JSON.parse(fs.readFileSync('.releaserc.json', 'utf8'));
  const analyzerEntry = releaserc.plugins.find(
    (entry) => Array.isArray(entry) && entry[0] === '@semantic-release/commit-analyzer'
  );
  if (!analyzerEntry) {
    throw new Error('commit-analyzer não encontrado em .releaserc.json');
  }
  const pluginConfig = analyzerEntry[1];

  const lastTag = execSync('git describe --tags --abbrev=0', { encoding: 'utf8' }).trim();
  const fromSha = execSync(`git rev-list -n 1 ${lastTag}`, { encoding: 'utf8' }).trim();

  const { getCommits } = await import('semantic-release/lib/git.js');
  const { analyzeCommits } = await import('@semantic-release/commit-analyzer');

  const logger = {
    log: (message) => console.log(message),
    error: (message) => console.error(message),
    success: (message) => console.log(message),
    warn: (message) => console.warn(message)
  };

  const commits = await getCommits(fromSha, 'HEAD', { cwd: process.cwd(), env: process.env });
  logger.log(`Found ${commits.length} commits since last release`);

  const releaseType = await analyzeCommits(pluginConfig, {
    commits,
    logger,
    cwd: process.cwd()
  });

  if (!releaseType) {
    console.log('Nenhum release necessário (commits desde a última tag não geram bump).');
    return;
  }

  const nextVersion = semver.inc(packageJson.version, releaseType);
  console.log(`Última tag: ${lastTag} (package.json: ${packageJson.version})`);
  console.log(`Tipo de release: ${releaseType}`);
  console.log(`Próxima versão: ${nextVersion}`);
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
