
#!/bin/bash

# The absolute path to the Python executable INSIDE your conda environment.
PYTHON_EXEC="/home/kali/miniconda3/envs/syn-apse/bin/python"

# We will NOT change directory. We rely on the `pip install -e .`
# command having made Python aware of where our package lives.
# This avoids the import ambiguity that caused the `RuntimeWarning`.

# Tell the correct Python interpreter to run the syn_apse.cli module as a script,
# and pass along all command-line arguments.
"$PYTHON_EXEC" -m syn_apse.cli "$@"
