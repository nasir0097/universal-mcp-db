pipeline {
    agent {
        docker {
            image 'python:3.13-slim'
            args '--network jenkins-net'
        }
    }

    environment {
        PIP_NO_CACHE_DIR    = '1'
        PYTHONDONTWRITEBYTECODE = '1'
    }

    stages {

        stage('Checkout') {
            steps {
                checkout scm
                echo "Branch: ${env.GIT_BRANCH ?: 'local'}"
                echo "Commit: ${env.GIT_COMMIT ?: 'unknown'}"
                sh 'python --version && pip --version'
            }
        }

        stage('Install') {
            steps {
                sh '''
                    pip install --upgrade pip -q
                    pip install -r requirements.txt -q
                    pip install pytest pytest-cov bandit httpx -q
                    apt-get update -qq && apt-get install -y -qq openssl 2>/dev/null || true
                    echo "=== Installed packages ==="
                    pip list | grep -E "fastapi|uvicorn|pytest|bandit|strawberry|hvac"
                    echo "=== OpenSSL version ==="
                    openssl version || echo "openssl not available"
                '''
            }
        }

        // ── Stage 1: Static security scan ─────────────────────────────────
        stage('Security Scan (bandit)') {
            steps {
                sh '''
                    python -m bandit -r . \
                        --exclude ./tests,./demo.db,./.git \
                        -ll \
                        -f json \
                        -o bandit-report.json || true
                    python -m bandit -r . \
                        --exclude ./tests,./demo.db,./.git \
                        -ll -f txt || true
                '''
            }
            post {
                always {
                    archiveArtifacts artifacts: 'bandit-report.json', allowEmptyArchive: true
                }
            }
        }

        // ── Stage 2: Unit + integration code tests ────────────────────────
        stage('Code Tests') {
            steps {
                sh '''
                    pytest tests/test_server.py \
                        -v --tb=short \
                        --junitxml=results-code.xml \
                        --cov=. --cov-report=xml:coverage-code.xml
                '''
            }
            post {
                always {
                    junit allowEmptyResults: true, testResults: 'results-code.xml'
                    archiveArtifacts artifacts: 'results-code.xml,coverage-code.xml',
                                     allowEmptyArchive: true
                }
            }
        }

        // ── Stage 3: Smoke tests ──────────────────────────────────────────
        stage('Smoke Tests') {
            steps {
                sh '''
                    pytest tests/test_smoke.py \
                        -v --tb=short \
                        --junitxml=results-smoke.xml
                '''
            }
            post {
                always {
                    junit allowEmptyResults: true, testResults: 'results-smoke.xml'
                    archiveArtifacts artifacts: 'results-smoke.xml', allowEmptyArchive: true
                }
            }
        }

        // ── Stage 4: Security injection tests ────────────────────────────
        stage('Security Tests (injection + roles)') {
            steps {
                sh '''
                    pytest tests/test_security.py \
                        -v --tb=short \
                        --junitxml=results-security.xml
                '''
            }
            post {
                always {
                    junit allowEmptyResults: true, testResults: 'results-security.xml'
                    archiveArtifacts artifacts: 'results-security.xml', allowEmptyArchive: true
                }
            }
        }

        // ── Stage 5: SQL chain tests ──────────────────────────────────────
        stage('SQL Chain Tests (MCP → SQL → result)') {
            steps {
                sh '''
                    pytest tests/test_sql_chain.py \
                        -v --tb=short \
                        --junitxml=results-sql-chain.xml
                '''
            }
            post {
                always {
                    junit allowEmptyResults: true, testResults: 'results-sql-chain.xml'
                    archiveArtifacts artifacts: 'results-sql-chain.xml', allowEmptyArchive: true
                }
            }
        }

        // ── Stage 6: OpenSSL / TLS tests ─────────────────────────────────
        stage('OpenSSL / TLS Tests') {
            steps {
                sh '''
                    pytest tests/test_openssl.py \
                        -v --tb=short \
                        --junitxml=results-openssl.xml
                '''
            }
            post {
                always {
                    junit allowEmptyResults: true, testResults: 'results-openssl.xml'
                    archiveArtifacts artifacts: 'results-openssl.xml', allowEmptyArchive: true
                }
            }
        }

        // ── Stage 7: Combined coverage report ────────────────────────────
        stage('Coverage Report') {
            steps {
                sh '''
                    pytest tests/ \
                        --tb=no -q \
                        --cov=. \
                        --cov-report=term-missing \
                        --cov-report=xml:coverage-full.xml \
                        --ignore=tests/test_openssl.py
                '''
            }
            post {
                always {
                    archiveArtifacts artifacts: 'coverage-full.xml', allowEmptyArchive: true
                }
            }
        }

        // ── Stage 8: Docker build ─────────────────────────────────────────
        stage('Docker Build') {
            agent any
            steps {
                sh '''
                    docker build \
                        -t universal-mcp-db:${BUILD_NUMBER} \
                        -t universal-mcp-db:latest \
                        .
                    echo "Built: universal-mcp-db:${BUILD_NUMBER}"
                    docker image inspect universal-mcp-db:latest --format "Size: {{.Size}} bytes"
                '''
            }
        }

    }

    post {
        success {
            echo """
╔══════════════════════════════════════╗
║  Build ${BUILD_NUMBER} PASSED                ║
║  All 8 stages green                  ║
╚══════════════════════════════════════╝
"""
        }
        failure {
            echo "Build ${BUILD_NUMBER} FAILED — check stage logs above"
        }
        always {
            cleanWs()
        }
    }
}
