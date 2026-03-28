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
- Fail build on threshold: `--failure_threshold high` returns non-zero exit code
