# Sources for the sample applications

| File | What it is |
|---|---|
| `corvane_sad.md`, `corvane_sad_draft.md`, `halcyon_sad.md` | SAD sources (Markdown; images link to the rendered diagrams) |
| `diagram.py`, `diagrams_a.py`, `diagrams_b.py` | Diagram definitions (boxes, zones, arrows) rendered to SVG |
| `render_png.js` | SVG to PNG with the pre-installed Playwright Chromium |
| `answer_keys.py` | Expected status of every control for each sample |
| `build_diagrams.py` → `build_docs.py` → `build_answer_keys.py` | Rebuild, in this order |

`build_docs.py` needs python-docx and LibreOffice (`soffice`) for the PDF.
If you change a SAD, update `answer_keys.py` so the answer key still matches;
`tests/test_samples.py` checks that each key covers exactly the controls its facets select.
