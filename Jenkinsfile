pipeline {
    agent any

    environment {
	SERVER_HOST = 'taehyung@host.docker.internal'
        SERVER_BASE = '/home/taehyung/apps/msa-server'
        SERVICE_DIR = 'gateway-service'
        COMPOSE_SERVICE = 'gateway-service'
        HEALTH_URL = 'https://api.erp007.xyz/api/gateway/health'
    }

    stages {
        stage('Deploy') {
            steps {
                sshagent(credentials: ['erp007-server-ssh']) {
                    sh """
                        ssh -o StrictHostKeyChecking=no ${SERVER_HOST} '
                            set -e
                            cd ${SERVER_BASE}/${SERVICE_DIR}
                            git pull --ff-only origin main

                            cd ${SERVER_BASE}/infra
                            docker compose -f docker-compose.yml -p msa-server up -d --build --no-deps ${COMPOSE_SERVICE}
                        '
                    """
                }
            }
        }

        stage('Health Check') {
            steps {
                sh '''
                    curl -fsS --retry 10 --retry-delay 3 --max-time 10 "$HEALTH_URL" >/dev/null
                '''
            }
        }
    }
}
