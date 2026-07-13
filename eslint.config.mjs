import { createConfig } from "eslint-config-nick2bad4u";

/** @type {import("eslint").Linter.Config[]} */
const config = [
    {
        ignores: [
            ".github/**",
            ".skillcheck-history.json",
            "_config.yml",
            "codecov.yml",
            "LICENSE",
            "pyproject.toml",
            "skills/**",
            "tests/**",
            "tools/**",
        ],
        name: "Python Skill And Repository Metadata Boundaries",
    },
    ...createConfig({
        allowDefaultProjectFilePatterns: [
            ".remarkrc.mjs",
            "eslint.config.mjs",
            "prettier.config.mjs",
            "stylelint.config.mjs",
            "tools/*.mjs",
        ],
    }),
    {
        name: "Repository Policy Compatibility",
        rules: {
            "repo-compliance/require-code-of-conduct-file": "off",
            "repo-compliance/require-codeowners-file": "off",
            "repo-compliance/require-gitattributes-file": "off",
            "repo-compliance/require-github-code-scanning-workflow": "off",
            "repo-compliance/require-license-spdx-identifier": "off",
            "repo-compliance/require-node-version-file": "off",
            "repo-compliance/require-nvmrc-file": "off",
            "repo-compliance/require-release-config-file": "off",
            "repo-compliance/require-secret-scanning-config": "off",
            "repo-compliance/require-support-file": "off",
        },
    },
];

export default config;
