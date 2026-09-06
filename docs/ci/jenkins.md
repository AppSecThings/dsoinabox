# Jenkins

```groovy
pipeline {
  agent any

  stages {
    stage('dsoinabox') {
      steps {
        sh '''
          set -e
          mkdir -p reports
          docker run --rm \
            -v "$WORKSPACE:/scan_target" \
            -v "$WORKSPACE/reports:/reports" \
            appsecthings/dsoinabox:latest \
            -t all \
            -o jenkins_html,sarif,json \
            --report_name dsoinabox \
            --failure_threshold high
        '''
      }
    }
  }

  post {
    always {
      archiveArtifacts artifacts: 'reports/**', allowEmptyArchive: true
    }
  }
}
```

- Mount repo: `-v "$WORKSPACE:/scan_target"`
- Persist artifacts: `archiveArtifacts artifacts: 'reports/**'`
- Gate: `--failure_threshold high` exits 1; a scanner failure exits 2; both are non-zero
- Newest reports are always under `reports/latest/` (`dsoinabox.sarif`, `dsoinabox.html`, ...)
