(venv) PS D:\VS Code\projects\HackathonIqbal> pip install fastapi uvicorn   
Collecting fastapi
  Using cached fastapi-0.137.0-py3-none-any.whl.metadata (26 kB)
Collecting uvicorn
  Using cached uvicorn-0.49.0-py3-none-any.whl.metadata (6.7 kB)
Collecting starlette>=0.46.0 (from fastapi)
  Using cached starlette-1.3.1-py3-none-any.whl.metadata (6.4 kB)
Collecting pydantic>=2.9.0 (from fastapi)
  Using cached pydantic-2.13.4-py3-none-any.whl.metadata (109 kB)
Collecting typing-extensions>=4.8.0 (from fastapi)
  Using cached typing_extensions-4.15.0-py3-none-any.whl.metadata (3.3 kB)
Collecting typing-inspection>=0.4.2 (from fastapi)
  Using cached typing_inspection-0.4.2-py3-none-any.whl.metadata (2.6 kB)
Collecting annotated-doc>=0.0.2 (from fastapi)
  Using cached annotated_doc-0.0.4-py3-none-any.whl.metadata (6.6 kB)
Collecting click>=7.0 (from uvicorn)
  Using cached click-8.4.1-py3-none-any.whl.metadata (2.6 kB)
Collecting h11>=0.8 (from uvicorn)
  Using cached h11-0.16.0-py3-none-any.whl.metadata (8.3 kB)
Collecting colorama (from click>=7.0->uvicorn)
  Using cached colorama-0.4.6-py2.py3-none-any.whl.metadata (17 kB)
Collecting annotated-types>=0.6.0 (from pydantic>=2.9.0->fastapi)
  Using cached annotated_types-0.7.0-py3-none-any.whl.metadata (15 kB)
Collecting pydantic-core==2.46.4 (from pydantic>=2.9.0->fastapi)
  Using cached pydantic_core-2.46.4.tar.gz (471 kB)
  Installing build dependencies ... error
  error: subprocess-exited-with-error
  
  × installing build dependencies for pydantic-core did not run successfully.
  │ exit code: 1
  ╰─> [32 lines of output]
      Collecting maturin<2,>=1.10
        Using cached maturin-1.14.0.tar.gz (367 kB)
        Installing build dependencies: started
        Installing build dependencies: finished with status 'done'
        Getting requirements to build wheel: started
        Getting requirements to build wheel: finished with status 'done'
        Installing backend dependencies: started
        Installing backend dependencies: finished with status 'done'
        Preparing metadata (pyproject.toml): started
        Preparing metadata (pyproject.toml): finished with status 'error'
        error: subprocess-exited-with-error
      
        Preparing metadata (pyproject.toml) did not run successfully.
        exit code: 1
      
        [5 lines of output]
        C:\Users\Asus\AppData\Local\Temp\pip-build-env-b8519ecy\overlay\lib\python3.14\site-packages\setuptools\_vendor\wheel\bdist_wheel.py:4: FutureWarning: The 'wheel' package is no longer the canonical location of the 'bdist_wheel' command, and will be removed in a future release. Please update to setuptools v70.1 or later which contains an integrated version of this command.
          warn(
        Python reports SOABI: cp314-mingw_x86_64_ucrt_gnu
        Unsupported platform: mingw_x86_64_ucrt_gnu
        Rust not found, installing into a temporary directory
        [end of output]
      
        note: This error originates from a subprocess, and is likely not a problem with pip.
      error: metadata-generation-failed
      
      Encountered error while generating package metadata.
      
      maturin
      
      note: This is an issue with the package mentioned above, not pip.
      hint: See above for details.
      [end of output]
  
  note: This error originates from a subprocess, and is likely not a problem with pip.
ERROR: Failed to build 'pydantic-core' when installing build dependencies for pydantic-core