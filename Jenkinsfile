pipeline {
    agent any

    options {
        timestamps()
        disableConcurrentBuilds()
    }

    environment {
        SERVER_HOST = 'taehyung@host.docker.internal'
        SERVER_BASE = '/home/taehyung/apps/msa-server'
        COMPOSE_SERVICE = 'gateway-service'
        REGISTRY_HOST = 'registry.erp007.xyz'
        HARBOR_PROJECT = 'erp007'
        HEALTH_URL = 'https://erp007.xyz/api/gateway/health'
    }

    stages {
        stage('Build Check') {
            when {
                not { branch 'main' }
            }
            steps {
                sh '''
                    set -eu
                    docker build -f "$SERVER_BASE/infra/docker/server-service.Dockerfile" .
                '''
            }
        }

        stage('Build and Push Image') {
            when { branch 'main' }
            steps {
                withCredentials([usernamePassword(credentialsId: 'harbor-robot-erp007', usernameVariable: 'HARBOR_USERNAME', passwordVariable: 'HARBOR_PASSWORD')]) {
                    sh '''
                        set -eu
                        git_sha="$(git rev-parse --short=12 HEAD)"
                        image_repo="${REGISTRY_HOST}/${HARBOR_PROJECT}/${COMPOSE_SERVICE}"
                        image_sha="${image_repo}:${git_sha}"
                        image_main="${image_repo}:main"

                        printf '%s' "$HARBOR_PASSWORD" | docker login "$REGISTRY_HOST" -u "$HARBOR_USERNAME" --password-stdin
                        docker build -f "$SERVER_BASE/infra/docker/server-service.Dockerfile" -t "$image_sha" -t "$image_main" .
                        docker push "$image_sha"
                        docker push "$image_main"
                        docker logout "$REGISTRY_HOST"
                    '''
                }
            }
        }

        stage('Deploy') {
            when { branch 'main' }
            steps {
                withCredentials([usernamePassword(credentialsId: 'harbor-robot-erp007', usernameVariable: 'HARBOR_USERNAME', passwordVariable: 'HARBOR_PASSWORD')]) {
                    sshagent(credentials: ['erp007-server-ssh']) {
                        sh '''
                            set -eu
                            printf '%s' "$HARBOR_PASSWORD" | ssh -o StrictHostKeyChecking=no "$SERVER_HOST" "docker login '$REGISTRY_HOST' -u '$HARBOR_USERNAME' --password-stdin"
                            ssh -o StrictHostKeyChecking=no "$SERVER_HOST" "
                                set -eu
                                cd '$SERVER_BASE/infra'
                                git pull --ff-only origin main
                                ./scripts/init-server-secrets.sh
                                docker compose -f docker-compose.yml -p msa-server config >/tmp/msa-server-compose.yml
                                docker compose -f docker-compose.yml -p msa-server pull '$COMPOSE_SERVICE'
                                docker compose -f docker-compose.yml -p msa-server up -d --no-deps '$COMPOSE_SERVICE'
                            "
                        '''
                    }
                }
            }
        }

        stage('Health Check') {
            when { branch 'main' }
            steps {
                sh '''
                    curl -fsS --retry 10 --retry-all-errors --retry-delay 3 --connect-timeout 5 --max-time 10 "$HEALTH_URL" >/dev/null
                '''
            }
        }
    }
}
