const { execSync } = require('child_process');
require('dotenv').config({ quiet: true });

try {
  if (!process.env.GH_TOKEN) {
    throw new Error('GH_TOKEN não encontrado no arquivo .env (necessário para release:dry:full)');
  }
  console.log('Prévia de release completa (semantic-release --dry-run)...');
  execSync('semantic-release --dry-run --no-ci', {
    stdio: 'inherit',
    env: {
      ...process.env,
      GITHUB_TOKEN: process.env.GH_TOKEN,
      GH_TOKEN: process.env.GH_TOKEN
    }
  });
  console.log('Dry-run concluído.');
} catch (error) {
  console.error('Erro durante o dry-run:', error.message);
  process.exit(1);
}
