import js from '@eslint/js';
import { configs, plugins } from 'eslint-config-airbnb-extended';

const jsConfig = [
  {files: ["**/*.ts"]},

  // ESLint Recommended Rules
  {
    name: 'js/config',
    ...js.configs.recommended,
  },
  // Stylistic Plugin
  plugins.stylistic,
  // Import X Plugin
  plugins.importX,
  // Airbnb Base Recommended Config
  ...configs.base.recommended
];

const nodeConfig = [
  // Node Plugin
  plugins.node,
  // Airbnb Node Recommended Config
  ...configs.node.recommended,
];

const typescriptConfig = [
  // TypeScript ESLint Plugin
  plugins.typescriptEslint,
  // Airbnb Base TypeScript Config
  ...configs.base.typescript,
  {
    files: [ '**/*.ts' ],
    languageOptions: {
      parserOptions: {
        projectService: false,
        project: './tsconfig.json',
        tsconfigRootDir: import.meta.dirname
      }
    }
  },
];

export default [
  // Ignore .gitignore files/folder in eslint
  // Javascript Config
  ...jsConfig,
  // Node Config
  ...nodeConfig,
  // TypeScript Config
  ...typescriptConfig,

  {
    rules: {
      '@stylistic/max-len': ['error', {
        code: 190,
        ignoreTemplateLiterals: true
      }],

      '@stylistic/object-curly-newline': ['error', {
        'ImportDeclaration': { "multiline": true },
      }],

      '@stylistic/array-bracket-spacing': ["error", "always"],
      '@stylistic/comma-dangle': ["error", "never"],
      'no-console': 'off',
      '@stylistic/quotes': 'off',
      'quote-props': ['error', 'consistent'],
      "no-return-await": "off",
      "import-x/order": "off",
      'n/no-process-exit': 'off',
      '@stylistic/arrow-parens': ["error", "as-needed"],
      "@typescript-eslint/consistent-type-definitions": ["error", "type"],
      "@typescript-eslint/return-await": ["error", "always"],
      '@stylistic/lines-between-class-members': 'off',
      "@stylistic/quote-props": ["error", "consistent"],

      // cloned from --print-config but removed for..of
      "no-restricted-syntax": [
        'error',
        {
          "selector": "ForInStatement",
          "message": "for..in loops iterate over the entire prototype chain, which is virtually never what you want. Use Object.{keys,values,entries}, and iterate over the resulting array."
        },
        {
          "selector": "LabeledStatement",
          "message": "Labels are a form of GOTO; using them makes code confusing and hard to maintain and understand."
        },
        {
          "selector": "WithStatement",
          "message": "`with` is disallowed in strict mode because it makes code impossible to predict and optimize."
        }
      ]
    }
  }
];
