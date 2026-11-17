import os, subprocess, sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).parent))
import diagrams_a
HERE = pathlib.Path(__file__).parent
JOBS = {
    "../corvane-supplier-hub/Corvane_SupplierHub_Architecture.png": diagrams_a.corvane_architecture,
}
try:
    import diagrams_b
    JOBS.update(diagrams_b.JOBS)
except ImportError:
    pass
for out, fn in JOBS.items():
    out = (HERE / out).resolve()
    out.parent.mkdir(parents=True, exist_ok=True)
    svg = out.with_suffix(".svg")
    tmp = HERE / ("_tmp_" + out.stem + ".svg")
    tmp.write_text(fn().to_svg())
    subprocess.run(["node", str(HERE / "render_png.js"), str(tmp), str(out)], check=True,
                   env={**os.environ, "NODE_PATH": subprocess.run(["npm", "root", "-g"], capture_output=True,
                                                                text=True).stdout.strip()})
    tmp.unlink()
    print("wrote", out)
