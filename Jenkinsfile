pipeline {
    agent none
    environment {
        // Kernel version for Ubuntu VMs
        KERNEL_VERSION='5.10.108'
        // Path to Ubuntu host VM image
        IMAGE_FILE='/img/ubuntu20-host.qcow2'
        // Location of guest patch file in kvms project
        PATCH_FILE='patches/guest/0001-kvm-encrypted-memory-draft-for-arm64-development.patch'
    }
    stages {
        stage('Clone project and build docker image') {
            agent { 
                node { 
                    label 'runner'
                    customWorkspace '/var/lib/jenkins/shared_workspace'}
            }
            steps {
                script {
                    sh 'rm -f *.log'
                    sh 'rm -f core*.*'
                    sh 'git config --global user.email "you@example.com"'
                    sh 'git config --global user.name "Your Name"'
                    sh 'cp ~/.gitconfig docker/gitconfig'
                    sh 'cd docker && docker build --build-arg userid=$(id -u) --build-arg groupid=$(id -g) --build-arg username=$(id -un) -t kvms .'
                    sh 'sudo chmod 0666 /dev/dri/render*'
                }
            }
        }
        stage('Run make in container'){
            agent {
                docker {
                    customWorkspace '/var/lib/jenkins/shared_workspace'
                    image 'kvms:latest'
                    args  '-v /ccache:/ccache -v ${WORKSPACE}:/hyp --env CCACHE_DIR=/ccache --env PLATFORM=virt --entrypoint='
                }
            }
            steps {
                sh 'cd /hyp && make clean || true'
                sh 'cd /hyp && make KERNEL_DIR=/hyp/oss/linux tools'
                sh 'cd /hyp && DEBUG=2 make KERNEL_DIR=/hyp/oss/linux'
            }
        }

        stage('Patch kernel image'){
            // run this directly in host, running nbd inside container was problematic
            agent { 
                node { 
                    label 'runner'
                    customWorkspace '/var/lib/jenkins/shared_workspace'}
            }
            steps {
                sh 'scripts/ci-check-kernel-patch.sh -k $KERNEL_VERSION -p $(pwd)/$PATCH_FILE -i $IMAGE_FILE'
            }
        }

        stage("Launch host and guest VMs") {
            agent {
                docker {
                        customWorkspace '/var/lib/jenkins/shared_workspace'
                        image 'kvms:latest'
                        args  '-d -t -v ${WORKSPACE}:/hyp -v /img:/img --env PLATFORM=virt --env BOOTIMG=${IMAGE_FILE} --name kvms_build_container --entrypoint= --privileged'
                    }
                }
            steps {
                sh 'cd /hyp && make KERNEL_DIR=/hyp/oss/linux GRAPHICS=1 run > /hyp/host.log &'

                sh 'echo wait for Host VM to reach Network Online state'
                sh 'timeout 240s grep -q "Network is Online" <(tail -f /hyp/host.log) || exit 1'
                // host VM is now accepting connections but it is better to give it more time to finalize startup
                sh 'sleep 60'

                sh 'echo HOST_IP=$(grep ssh /hyp/host.log | cut -d" " -f7|cut -d":" -f1) > host_ips.sh'
                sh 'cat host_ips.sh'
                sh '''
                    source host_ips.sh
                    echo \$HOST_IP
                    sshpass -p ubuntu ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no ubuntu@\$HOST_IP -p 10022 "sudo systemctl stop unattended-upgrades"
                    sshpass -p ubuntu ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no ubuntu@\$HOST_IP -p 10022 "sudo rm -rf /var/lib/apport/coredump/*"
                    sshpass -p ubuntu scp -P 10022 -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no linux-5.10.108/arch/arm64/boot/Image ubuntu@172.17.0.2:~/vm/ubuntu20
                    sshpass -p ubuntu ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no ubuntu@\$HOST_IP -p 10022 "cd vm/ubuntu20 && ulimit -c unlimited && sudo ./run-qemu6-linux.sh > guest.log" &
                    echo $?
                '''

                sh 'echo wait for Guest VM to reach Network Online state'
                sh '''
                    source host_ips.sh
                    echo "giving a lot of time for guest VM to start"
                    sleep 480
                    sshpass -p ubuntu ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no ubuntu@\$HOST_IP -p 10022 "cat vm/ubuntu20/guest.log"
                    timeout 240s grep -q "Network is Online" <(sshpass -p ubuntu ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no ubuntu@\$HOST_IP -p 10022 "tail -f vm/ubuntu20/guest.log") || true
                    sshpass -p ubuntu ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no ubuntu@\$HOST_IP -p 10022 "cat vm/ubuntu20/guest.log" >>/hyp/guest_nw.log
                    sleep 60
                '''
                sh '''
                    source host_ips.sh
                    sshpass -p ubuntu ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no ubuntu@$HOST_IP -p 10022 "cat vm/ubuntu20/guest.log" >/hyp/guest.log
                    sshpass -p ubuntu ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no ubuntu@$HOST_IP -p 10022 "dmesg" >/hyp/host-dmesg.log
                    sshpass -p ubuntu ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no ubuntu@$HOST_IP -p 10022 "sudo chmod 444 /var/lib/apport/coredump/* || true"
                    sshpass -p ubuntu scp -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -P10022 ubuntu@$HOST_IP:/var/lib/apport/coredump/* /hyp || true
                '''

                sh 'echo GUEST1_IP=$(grep ssh /hyp/guest.log | cut -d" " -f7|cut -d":" -f1) >> host_ips.sh'
                sh '''
                    source host_ips.sh
                    sshpass -p ubuntu ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no ubuntu@$HOST_IP -p 10022 ssh ubuntu@$GUEST1_IP -p 2000 "dmesg" > /hyp/guest1-dmesg.log
                    sshpass -p ubuntu ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no ubuntu@$HOST_IP -p 10022 ssh ubuntu@$GUEST1_IP -p 2000 "sudo systemctl stop unattended-upgrades"
                    sshpass -p ubuntu ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no ubuntu@$HOST_IP -p 10022 ssh ubuntu@$GUEST1_IP -p 2000 "ps aux" > /hyp/guest1-ps.log
                    sshpass -p ubuntu ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no ubuntu@$HOST_IP -p 10022 ssh ubuntu@$GUEST1_IP -p 2000 "sudo shutdown now" || true
                    
                '''
                sh 'echo wait for Guest VM to reach Power-Offstate'
                sh '''
                    source host_ips.sh
                    timeout 240s grep -q "Power-Off" <(sshpass -p ubuntu ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no ubuntu@$HOST_IP -p 10022 "tail -f vm/ubuntu20/guest.log") || exit 1
                '''
                sh '''
                    source host_ips.sh
                    sshpass -p ubuntu ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no ubuntu@$HOST_IP -p 10022 "ps aux"
                    sshpass -p ubuntu ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no ubuntu@$HOST_IP -p 10022 "cat vm/ubuntu20/guest.log" >/hyp/guest_shutdown.log
                    sshpass -p ubuntu ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no ubuntu@$HOST_IP -p 10022 "sudo shutdown now" || true
                '''
                sh 'sleep 30'
            }

            post {
                always {
                    archiveArtifacts artifacts: '*.log', followSymlinks: false, allowEmptyArchive: true
                    archiveArtifacts artifacts: 'core*.*', followSymlinks: false, allowEmptyArchive: true
                    }
                success {
                    script {
                        if (env.GITHUB_PR_SOURCE_BRANCH) {
                                githubPRComment comment: githubPRMessage("[build passed: ${BUILD_NUMBER}](${BUILD_URL})."), statusVerifier: allowRunOnStatus("SUCCESS"), errorHandler: statusOnPublisherError("UNSTABLE")
                        }
                    }
                }
                failure{
                    script {
                        if (env.GITHUB_PR_SOURCE_BRANCH) {
                                githubPRComment comment: githubPRMessage("[build failed: ${BUILD_NUMBER}](${BUILD_URL})."), statusVerifier: allowRunOnStatus("FAILURE"), errorHandler: statusOnPublisherError("UNSTABLE")
                        }
                    }
                }
            }
        }
    }
}