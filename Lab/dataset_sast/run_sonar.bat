@echo off
sonar-scanner ^
  -Dsonar.projectKey=juice-shop-replication ^
  -Dsonar.projectName="Juice Shop Replication" ^
  -Dsonar.sources=. ^
  -Dsonar.inclusions=**/*.ts ^
  -Dsonar.host.url=http://localhost:9000 ^
  -Dsonar.token=sqp_4a4b3d05ddf8f3bb3f4853d058ee1f9632e642f5
pause