// @loose/web ESLint config: root config + React Hooks rules.
import reactHooks from 'eslint-plugin-react-hooks';
import rootConfig from '../../eslint.config.js';

export default [
  ...rootConfig,
  {
    files: ['**/*.{ts,tsx}'],
    plugins: { 'react-hooks': reactHooks },
    rules: {
      ...reactHooks.configs.recommended.rules,
    },
  },
];
