export default [
  { ignores: ["node_modules/**", ".osint-power/**"] },
  {
    files: ["**/*.js"],
    languageOptions: { ecmaVersion: "latest", sourceType: "module" },
    rules: {
      "no-unused-vars": [
        "error",
        { argsIgnorePattern: "^_", caughtErrorsIgnorePattern: "^_" },
      ],
      "no-unreachable": "error",
      "no-constant-condition": ["error", { checkLoops: false }],
      eqeqeq: "error",
      "no-var": "error",
    },
  },
];
