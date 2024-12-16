pipeline {
    environment {
        PRE_COMMIT_HOME = "${WORKSPACE}/.cache"
    }
    agent {
        docker {
            label 'ec2-fleet'
            image "python:3.13"
            reuseNode true
        }
    }
    stages {
        stage('Checkout') {
            steps {
                checkout scm
            }
        }
        stage('Set up Python and Cache') {
            steps {
                script {
                    sh 'python -m venv venv'
                    sh '''
                        . venv/bin/activate
                        python --version
                        pip install uv
                        uv pip install -r requirements-dev.txt --no-cache
                    '''
                    stash includes: 'venv/**', name: 'venv'
                    sh '''
                        . venv/bin/activate
                        pre-commit install-hooks
                    '''
                }
            }
        }
        stage('Run Linters') {
            matrix {
                axes {
                    axis {
                        name 'LINTER'
                        values 'ruff-format', 'ruff', 'mypy', 'check-json', 'codespell'
                    }
                }
                stages {
                    stage('Lint') {
                        steps {
                            script {
                                sh '''
                                    . venv/bin/activate
                                    pre-commit run --hook-stage manual ${LINTER} --all-files --show-diff-on-failure
                                '''
                            }
                        }
                    }
                }
            }
        }

        stage('Run Tests') {
            steps {
                script {
                    unstash 'venv'
                    sh '''
                        . venv/bin/activate
                        python --version
                        python -m coverage run -m unittest discover -s tests
                        python -m coverage report --fail-under=100
                    '''
                }
            }
        }

    }
}
