// This module intentionally contains no Go code.
//
// Its only purpose is to stop the parent module's `./...` package patterns
// from traversing into apps/web (and node_modules, which vendors stray Go
// packages such as flatted). The UI is built with npm; see package.json.
module github.com/bukansembarangkong/jawaker-panel/apps/web

go 1.26
