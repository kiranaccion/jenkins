// Jenkinsfile for golden_set_collector.py
// Put this next to golden_set_collector.py in the same repo.
//
// One-time Jenkins setup:
//   1. Manage Jenkins > Credentials > add a "Secret text" credential with id
//      'github-readonly-token' (fine-grained token, Actions:read + Metadata:read,
//      limited to the repos you list).
//   2. Use an agent that has python3 (3.9+) and network access to api.github.com
//      (or your GHES host). Change the label below to match your agent.
//   3. Make sure DATA_DIR exists on that agent and is readable only by the
//      jenkins user (the output contains redacted-but-confidential logs).

pipeline {
    agent { label 'python' }

    options {
        timestamps()
        disableConcurrentBuilds()      // the collector appends to one jsonl file
        timeout(time: 6, unit: 'HOURS') // rate-limit sleeps can be long
        buildDiscarder(logRotator(numToKeepStr: '30'))
    }

    // Uncomment to collect weekly (GitHub keeps logs ~90 days, so don't wait too long)
    // triggers { cron('H 2 * * 1') }

    parameters {
        choice(name: 'COMMAND', choices: ['selftest', 'inventory', 'collect', 'split'],
               description: 'Run selftest first, then inventory, then a small collect trial, then the full run.')
        text(name: 'REPOS', defaultValue: 'org/repo-one\norg/repo-two',
             description: 'One owner/repo per line')
        string(name: 'DAYS', defaultValue: '90', description: 'Look-back window in days')
        booleanParam(name: 'INCLUDE_RECOVERED', defaultValue: true,
                     description: 'Also collect failed attempts of runs that passed after a re-run')
        string(name: 'MAX_RECORDS', defaultValue: '20',
               description: 'collect only: stop after N records (use 0 for a full run)')
        string(name: 'HOLDOUT_REPOS', defaultValue: '',
               description: 'split only: comma-separated repos used only for the test set')
        string(name: 'API_URL', defaultValue: 'https://api.github.com',
               description: 'Change only for GitHub Enterprise Server')
        string(name: 'DATA_DIR', defaultValue: '/var/lib/jenkins/devrer-data',
               description: 'Persistent folder on the agent. Keeps raw_candidates.jsonl between builds so collect can resume.')
    }

    environment {
        GITHUB_TOKEN = credentials('github-readonly-token')
    }

    stages {
        stage('Setup Python') {
            steps {
                sh '''
                    python3 -m venv .venv
                    . .venv/bin/activate
                    pip install --quiet --upgrade pip requests
                    mkdir -p "$DATA_DIR"
                '''
            }
        }

        stage('Write repos file') {
            when { expression { params.COMMAND in ['inventory', 'collect'] } }
            steps {
                writeFile file: 'repos.txt', text: params.REPOS
            }
        }

        stage('Run') {
            steps {
                script {
                    def common = "--repos-file repos.txt --days ${params.DAYS} --api-url ${params.API_URL} --out '${params.DATA_DIR}'"
                    def recovered = params.INCLUDE_RECOVERED ? '--include-recovered' : ''
                    def cmd = ''
                    switch (params.COMMAND) {
                        case 'selftest':
                            cmd = 'python golden_set_collector.py selftest'
                            break
                        case 'inventory':
                            cmd = "python golden_set_collector.py inventory ${common} ${recovered}"
                            break
                        case 'collect':
                            def maxRec = (params.MAX_RECORDS && params.MAX_RECORDS != '0') ? "--max-records ${params.MAX_RECORDS}" : ''
                            cmd = "python golden_set_collector.py collect ${common} ${recovered} ${maxRec}"
                            break
                        case 'split':
                            def holdout = params.HOLDOUT_REPOS?.trim() ? "--holdout-repos '${params.HOLDOUT_REPOS.trim()}'" : ''
                            cmd = "python golden_set_collector.py split --in '${params.DATA_DIR}/raw_candidates.jsonl' --out '${params.DATA_DIR}' ${holdout}"
                            break
                    }
                    // Token is injected by credentials(); single quotes avoid leaking it via Groovy interpolation.
                    sh ". .venv/bin/activate && ${cmd}"
                }
            }
        }
    }

    post {
        success {
            script {
                // Only the non-sensitive summaries are archived. Raw logs/excerpts stay in DATA_DIR on the agent.
                if (params.COMMAND == 'inventory') {
                    sh "cp '${params.DATA_DIR}/inventory.csv' ."
                    archiveArtifacts artifacts: 'inventory.csv', fingerprint: true
                } else if (params.COMMAND == 'split') {
                    sh "cp '${params.DATA_DIR}/coverage_report.txt' ."
                    archiveArtifacts artifacts: 'coverage_report.txt', fingerprint: true
                }
            }
        }
        cleanup {
            sh 'rm -rf .venv repos.txt'
        }
    }
}
