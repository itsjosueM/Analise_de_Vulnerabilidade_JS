@echo off
sonar-scanner ^
  -Dsonar.projectKey=juice-shop-replication ^
  -Dsonar.projectName="Juice Shop Replication" ^
  -Dsonar.sources=. ^
  -Dsonar.inclusions=**/*.ts ^
  -Dsonar.host.url=http://localhost:9000 ^
  -Dsonar.token=sqp_99564444635e0f9428b8fe2213ff6492bcac4678
pause