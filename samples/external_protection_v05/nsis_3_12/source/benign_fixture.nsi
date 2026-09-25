; VulnAgent V0.5 teaching matrix - level 2 (NSIS container) fixture.
; Rebuilt locally 2026-09-25 from the benign baseline program only.
; This installer/container is not executed; static analysis only.

Name "VulnAgent benign fixture"
OutFile "..\bin\benign_cli_nsis_3.12_setup.exe"
RequestExecutionLevel user
SilentInstall silent

Section
  SetOutPath "$INSTDIR"
  File "..\..\upx_5_2_0\bin\benign_cli_plain.exe"
SectionEnd