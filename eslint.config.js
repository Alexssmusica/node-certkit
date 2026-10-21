import eslint from '@eslint/js';
import eslintPluginPrettierRecommended from 'eslint-plugin-prettier/recommended';
import { defineConfig } from 'eslint/config';
import globals from 'globals';
import tseslint from 'typescript-eslint';

export default defineConfig(
  {
    ignores: [
      'eslint.config.mjs',
      'node_modules',
      'lib',
      'dist',
      '*.js',
      'vitest.config.mts',
      'examples',
      'tests/types/dts-consumer-usage.ts'
    ]
  },
  eslint.configs.recommended,
  ...tseslint.configs.recommendedTypeChecked,
  eslintPluginPrettierRecommended,
  {
    languageOptions: {
      globals: {
        ...globals.node
      },
      ecmaVersion: 2024,
      sourceType: 'module',
      parserOptions: {
        projectService: true,
        tsconfigRootDir: import.meta.dirname
      }
    }
  },
  {
    rules: {
      'prettier/prettier': 'warn',
      'no-var': 'error',
      'prefer-const': 'error',
      'id-length': [
        'warn',
        {
          min: 3,
          properties: 'never'
        }
      ],
      '@typescript-eslint/naming-convention': [
        'warn',
        {
          selector: 'variableLike',
          format: ['camelCase', 'PascalCase', 'UPPER_CASE'],
          leadingUnderscore: 'allow',
          filter: {
            regex:
              '^(encode_rsa_oaep|decode_rsa_oaep|bad_certificate|unknown_ca|certificate_expired|unsupported_certificate|certificate_revoked|certificate_unknown)$',
            match: false
          }
        },
        {
          selector: 'parameter',
          format: ['camelCase'],
          leadingUnderscore: 'allow'
        }
      ],
      'no-shadow': 'off',
      '@typescript-eslint/no-shadow': 'warn'
    }
  },
  {
    files: ['tests/**/*.ts'],
    languageOptions: {
      parserOptions: {
        projectService: false,
        project: ['./tsconfig.test.json'],
        tsconfigRootDir: import.meta.dirname
      }
    },
    rules: {
      eqeqeq: 'error',
      'prefer-template': 'error',
      'prefer-arrow-callback': 'error',
      'id-length': 'off',
      'id-denylist': 'off',
      '@typescript-eslint/naming-convention': 'off',
      '@typescript-eslint/no-shadow': 'off'
    }
  }
);
