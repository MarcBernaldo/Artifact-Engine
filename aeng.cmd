@echo off
REM Lanzador de Artifact Engine. Uso: aeng setup  |  aeng run -p "C:\ruta"
REM Equivale a: python -m artifact_engine <args>
python -m artifact_engine %*
