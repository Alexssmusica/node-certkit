import eslint from '@eslint/js';
import eslintPluginPrettierRecommended from 'eslint-plugin-prettier/recommended';
import globals from 'globals';
import tseslint from 'typescript-eslint';

export default tseslint.config(
  {
    ignores: ['eslint.config.mjs', 'node_modules', 'lib', 'dist', 'tests', '*.js', 'vitest.config.mts', 'examples']
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
      '@typescript-eslint/no-unused-expressions': 'off',
      '@typescript-eslint/no-unnecessary-type-constraint': 'off',
      '@typescript-eslint/ban-ts-comment': 'off',
      '@typescript-eslint/no-namespace': 'off',
      '@typescript-eslint/no-duplicate-enum-values': 'off',
      '@typescript-eslint/no-unnecessary-type-assertion': 'off',
      '@typescript-eslint/no-explicit-any': 'off',
      '@typescript-eslint/prefer-promise-reject-errors': 'off',
      'no-irregular-whitespace': 'off',
      '@typescript-eslint/no-unused-vars': 'off',
      '@typescript-eslint/only-throw-error': 'off',
      '@typescript-eslint/no-floating-promises': 'off',
      '@typescript-eslint/no-unsafe-member-access': 'off',
      '@typescript-eslint/no-redundant-type-constituents': 'off',
      '@typescript-eslint/no-unsafe-assignment': 'off',
      '@typescript-eslint/no-unsafe-argument': 'off',
      '@typescript-eslint/no-misused-promises': 'off',
      '@typescript-eslint/await-thenable': 'off',
      '@typescript-eslint/unbound-method': 'off',
      '@typescript-eslint/restrict-plus-operands': 'off',
      '@typescript-eslint/no-unsafe-enum-comparison': 'off',
      '@typescript-eslint/no-unsafe-call': 'off',
      '@typescript-eslint/no-empty-object-type': 'off',
      '@typescript-eslint/no-base-to-string': 'off',
      '@typescript-eslint/require-await': 'off',
      '@typescript-eslint/no-unsafe-function-type': 'off',
      '@typescript-eslint/restrict-template-expressions': 'off',
      '@typescript-eslint/no-require-imports': 'off',
      '@typescript-eslint/no-unsafe-return': 'off',
      'no-empty': 'off',
      'no-control-regex': 'off',
      'no-case-declarations': 'off',
      'no-fallthrough': 'off',
      'no-useless-escape': 'off',
      'prefer-rest-params': 'off'
    }
  },
  {
    files: ['src/domain/math/BigInteger.ts'],
    rules: {
      'prefer-const': 'off'
    }
  }
);
