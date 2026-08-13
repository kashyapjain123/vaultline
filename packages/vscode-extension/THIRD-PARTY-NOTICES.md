# Third-Party Notices

Vaultline is licensed under Apache-2.0 (see [LICENSE](LICENSE)). It also
redistributes third-party software, and the platform-specific builds
redistribute compiled native binaries and machine-learning model weights.
Those obligations travel with the artifact, so this file lives in the
extension package and **ships inside every .vsix** rather than sitting at the
repository root where an installed user would never see it.

**Two builds ship different things**, so the obligations differ:

| Build | What it contains |
|---|---|
| **Portable** (`vaultline-<version>.vsix`, ~4.6MB) | The extension, `@vaultline/core`, the tree-sitter runtime and grammars, and the embedding server's *source only*. Dependencies are installed on the user's machine at first run and are never redistributed by us. |
| **Platform-specific** (`vaultline-<version>-<os>-<arch>.vsix`, ~65MB) | All of the above **plus** the embedding server's full dependency tree as prebuilt native binaries, **plus** the all-MiniLM-L6-v2 model weights. |

---

## Shipped in every build

### web-tree-sitter — MIT

Incremental parsing runtime, used for comment-aware suppression.
https://github.com/tree-sitter/tree-sitter

### tree-sitter-wasms — Unlicense

Precompiled WebAssembly tree-sitter grammars.
https://github.com/Gregoor/tree-sitter-wasms

The package itself is released under the Unlicense (public-domain
dedication). The individual **grammars** it compiles are separate upstream
projects, each under its own licence — predominantly MIT, some Apache-2.0.
Their licences live in their respective `tree-sitter-<language>`
repositories under https://github.com/tree-sitter.

---

## Shipped only in platform-specific builds

These arrive via `embedding-server`'s dependency tree. A licence census of
that installed tree at the time of writing:

| Licence | Packages |
|---|---|
| MIT | 106 |
| BSD-3-Clause | 13 |
| Apache-2.0 | 13 |
| ISC | 8 |
| (MIT OR WTFPL) | 1 — `expand-template` |
| (BSD-2-Clause OR MIT OR Apache-2.0) | 1 — `rc` |
| Apache-2.0 (declared as "SEE LICENSE IN LICENSE.txt") | 1 — `flatbuffers` |

All are permissive and redistributable. The direct dependencies that matter
most:

### @xenova/transformers — Apache-2.0

Transformers.js; runs the embedding model.
https://github.com/xenova/transformers.js

### onnxruntime-node, onnxruntime-web — MIT

ONNX Runtime, Microsoft. Ships prebuilt native binaries per platform;
platform builds keep only the target's.
https://github.com/microsoft/onnxruntime

### sharp — Apache-2.0

Image processing. **Not used by Vaultline** — it is a hard static import of
transformers.js (`utils/image.js`), so it cannot be pruned even though this
server only ever embeds text.
https://github.com/lovell/sharp

#### ⚠ sharp's vendored binaries include LGPLv3 libraries

This is the only copyleft component anywhere in Vaultline's distribution, and
it applies **only to platform-specific builds**, which redistribute the
binaries rather than installing them on the user's machine.

sharp bundles prebuilt shared libraries, of which these are **LGPLv3** (via
the "any later version" clause of LGPLv2/LGPLv2.1):

`libvips` · `glib` · `pango` · `librsvg` · `gdk-pixbuf` · `fribidi` ·
`libexif` · `libheif` · `proxy-libintl`

The remainder are MIT, BSD-2-Clause or BSD-3-Clause. The authoritative,
per-platform list ships inside the package at:

```
node_modules/sharp/vendor/<version>/<platform>/THIRD-PARTY-NOTICES.md
```

**LGPL compliance rests on three things**, all of which hold here: the
libraries are used **unmodified**; they are **dynamically linked** as
separate shared objects (`.dylib` / `.so` / `.dll`), so a user can replace
them; and their notices ship alongside them. That last point is enforced in
`scripts/stageCore.js`, which deliberately exempts licence and notice files
from the markdown stripping it otherwise applies to dependencies — see the
comment there before changing it.

Sources: https://github.com/libvips/libvips and the upstream project for each
library listed above.

### protobufjs — BSD-3-Clause

https://github.com/protobufjs/protobuf.js

### flatbuffers — Apache-2.0

https://github.com/google/flatbuffers

---

## Model weights

### sentence-transformers/all-MiniLM-L6-v2 — Apache-2.0

Sentence-embedding model used for similarity routing, whole-message
business-content classification, and semantic keyword matching. Platform
builds bundle the quantised ONNX conversion published as
**Xenova/all-MiniLM-L6-v2** (~23MB) so installs work offline; the portable
build downloads it from Hugging Face on first run.

- Original: https://huggingface.co/sentence-transformers/all-MiniLM-L6-v2
- ONNX conversion: https://huggingface.co/Xenova/all-MiniLM-L6-v2

---

## Regenerating this file

The census above comes from the installed dependency tree, not from a
hand-maintained list. To re-derive it after a dependency change:

```bash
cd packages/core/embedding-server && npm install --omit=dev
node -e "
const fs=require('fs'), path=require('path'), root='node_modules', counts={};
for (const dir of fs.readdirSync(root)) {
  const pkgs = dir.startsWith('@') ? fs.readdirSync(path.join(root,dir)).map(d=>path.join(dir,d)) : [dir];
  for (const p of pkgs) {
    try {
      const j = JSON.parse(fs.readFileSync(path.join(root,p,'package.json'),'utf8'));
      const l = typeof j.license==='string' ? j.license : (j.license||{}).type || 'UNKNOWN';
      counts[l] = (counts[l]||0)+1;
    } catch {}
  }
}
console.log(counts);
"
```

Anything appearing there that is **not** permissive — in particular any
GPL/AGPL family licence — needs review before shipping a platform build,
since those builds redistribute the binaries rather than installing them on
the user's machine.
