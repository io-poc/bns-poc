def isSASTEnabled
def isSASTPlusMEnabled
def isSCAEnabled
def isDASTEnabled
def isDASTPlusMEnabled


pipeline {
    agent any
    stages {
        stage('Checkout Source Code') {
            steps {
                git branch: 'master', url: 'https://github.com/io-poc/bns-poc'
            }
        }

        stage('Build Source Code') {
            steps {
                  withMaven {
                      sh '''mvn clean package -Dmaven.test.skip'''
                  }
            }
        }

        stage('IO - Prescription') {
            steps {
                synopsysIO(connectors: [
                    io(
                        configName: 'poc-io',
                        projectName: 'insecure-bank',
                        workflowVersion: '2021.12.4'),
                    github(
                        branch: 'master',
                        configName: 'poc-github',
                        owner: 'io-poc',
                        repositoryName: 'bns-poc'), 
                     jira(
                         assignee: 'karn@synopsys.com', 
                         configName: 'poc-jira', 
                         issueQuery: 'resolution=Unresolved', 
                         projectKey: 'INSEC', 
                         projectName: 'insecure-bank'), 
                    buildBreaker(configName: 'poc-bb')]) {
                        sh 'io --stage io Persona.Type=devsecops Project.Release.Type=minor'
                    }

                script {
                    def prescriptionJSON = readJSON file: 'io_state.json'

                    isSASTEnabled = prescriptionJSON.data.prescription.security.activities.sast.enabled
                    isSASTPlusMEnabled = prescriptionJSON.data.prescription.security.activities.sastPlusM.enabled
                    isSCAEnabled = prescriptionJSON.data.prescription.security.activities.sca.enabled
                    isDASTEnabled = prescriptionJSON.data.prescription.security.activities.dast.enabled
                    isDASTPlusMEnabled = prescriptionJSON.data.prescription.security.activities.dastPlusM.enabled
                    isImageScanEnabled = prescriptionJSON.data.prescription.security.activities.imageScan.enabled

                }
            }
        }


        stage('SAST - Polaris') {
            when {
                expression { isSASTEnabled }
            }
            steps {
                echo 'Running SAST using Polaris'
                synopsysIO(connectors: [
                    [$class: 'PolarisPipelineConfig',
                    configName: 'poc-polaris',
                    projectName: 'insecure-bank']]) {
                    sh 'io --stage execution --state io_state.json'
                }
            }
        }

        stage('SAST Plus Manual') {
            when {
                expression { isSASTPlusMEnabled }
            }
            steps {
                script {
                    input message: 'Manual source code review (SAST - Manual) triggered by IO. Proceed?'
                }
                echo "Out-of-Band Activity - SAST Plus Manual triggered & approved"
            }
        } 

        stage('SCA - BlackDuck') {
            when {
                expression { isSCAEnabled }
            }
            steps {
              echo 'Running SCA using BlackDuck'
              synopsysIO(connectors: [
                  blackduck(configName: 'poc-bd',
                  projectName: 'insecure-bank',
                  projectVersion: '1.0')]) {
                  sh 'io --stage execution --state io_state.json'
              }
            }
        } 

        stage('DAST Plus Manual') {
            when {
                expression { isDASTPlusMEnabled }
            }
            steps {
                script {
                    input message: 'Manual threat-modeling (DAST - Manual) triggered by IO. Proceed?'
                }
                echo "Out-of-Band Activity - DAST Plus Manual triggered & approved"
            }
        }

        stage('IO - Workflow') {
            steps {
                echo 'Execute Workflow Stage'
                synopsysIO(connectors: [
                    codeDx(configName: 'poc-codedx', projectId: '1'), 
                    jira(assignee: 'karn@synopsys.com', configName: 'poc-jira', issueQuery: 'resolution=Unresolved AND labels in (Security, Defect)', projectKey: 'INSEC'), 
                    //msteams(configName: 'poc-msteams'), 
                    buildBreaker(configName: 'poc-bb')
                ]) {
                    sh 'io --stage workflow --state io_state.json'
                }
                
                 script {
                    def workflowJSON = readJSON file: 'wf-output.json'
                    print("========================== IO WorkflowEngine Summary ============================")
                    print("Breaker Status: $workflowJSON.breaker.status")
                } 
            }
        }
        
        stage('Security Sign-Off') {
            steps {
                script {

                    def workflowJSON = readJSON file: 'wf-output.json'
                    
                    
                    //Build Breaker
                    if(workflowJSON.breaker.status==true) {
                          echo "Sending Notifications to Teams..."
                          sh 'curl -H \'Content-Type: application/json\' -d \'{"text": "Breaking the build for application: Insecure Bank"}\' "https://synopsyssig.webhook.office.com/webhookb2/ce20f176-4d07-41c8-8a7b-cf6c66254b84@99f3f5c1-a294-451e-9e1e-b3bbc8d9e4ba/IncomingWebhook/dd5340edfc7144cfa752da8f33dcdc6b/19b0d4ae-c36c-423e-b436-2a4780775ce3"'
                          echo "Insecure-Bank has identified vulnerabilities and it requires your attention!"
                          //exit 1
                    }
                    
                    codedx_value = workflowJSON.summary.risk_score
                    for(arr in codedx_value){
                        if(arr != null)
                        {   
                            print("Code Dx Score: $arr")
                            if(arr < 80)
                            {
                                input message: 'Code Dx Score did not meet the defined threshold. Do you wish to proceed?'
                            }
                        }
                    }
                    
                }
                echo "Security Sign-Off triggered & approved"
            }
        } 
    }

}
