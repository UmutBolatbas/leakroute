# Vendored grammars

| File                      | Source                                                                                                                      | Version | License                               | SHA-256                                                            |
| ------------------------- | --------------------------------------------------------------------------------------------------------------------------- | ------- | ------------------------------------- | ------------------------------------------------------------------ |
| `tree-sitter-python.wasm` | npm package [`tree-sitter-python`](https://www.npmjs.com/package/tree-sitter-python) (prebuilt file shipped in the package) | 0.25.0  | MIT, see `LICENSE-tree-sitter-python` | `16108b50df4ee9a30168794252ab55e7c93bfc5765d7fa0aa3e335752c515f47` |

The WASM file is committed instead of depending on the npm package because that
package also builds a native Node addon on install, which leakroute does not need.

To update: `npm pack tree-sitter-python@<version>`, copy `package/tree-sitter-python.wasm`
and `package/LICENSE` here, update this table, and run the test suite. The grammar's
ABI must be supported by the installed `web-tree-sitter`.
