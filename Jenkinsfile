pipeline {
    agent none
    stages {
        stage('Clone project and build docker image') {
            agent any
            steps {
                script {
                    sh 'env'
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
            // run this stage only when there are changes in patches folder
            // this is risky as kernel modules from previously patch change will be re-used in next pipeline
            // it is possible that change meant to be built on top of master versoin of patch gets built from kernel patch from PR
            // when { changeset "patches/*"}
            agent any
            steps {
                sh 'sudo modprobe nbd max_part=8'
                sh 'sudo scripts/update_kernel_to_ubuntu_VMs.sh -i /img/ubuntu20-host.qcow2'
            }
        }

        stage("Launch host and guest VMs") {
            agent {
                docker {
                        image 'kvms:latest'
                        args  '-d -t -v ${WORKSPACE}:/hyp -v /img:/img --env PLATFORM=virt --env BOOTIMG=/img/ubuntu20-host.qcow2 --name kvms_build_container --entrypoint= --privileged'
                    }
                }
            steps {
                sh 'cd /hyp && make KERNEL_DIR=/hyp/oss/linux GRAPHICS=1 run > /hyp/host.log &'
                sh 'sleep 240'

                sh 'echo HOST_IP=$(grep ssh /hyp/host.log | cut -d" " -f7|cut -d":" -f1) > host_ips.sh'
                sh 'cat host_ips.sh'
                sh '''
                    source host_ips.sh
                    echo \$HOST_IP
                    echo setting up ssh keys for host VM
                    rm -f hostkey*
                    mkdir -p ~/.ssh
                    ssh-keygen -b 2048 -t rsa -f hostkey -q -N ""
                    ssh-keyscan -p 10022 \$HOST_IP >> ~/.ssh/known_hosts
                    sshpass -p ubuntu ssh-copy-id -i hostkey -p 10022 ubuntu@\$HOST_IP

                    ssh -i hostkey ubuntu@\$HOST_IP -p 10022 "sudo rm -rf /var/lib/apport/coredump/*"
                    scp -P 10022 -i hostkey linux-5.10.108/arch/arm64/boot/Image ubuntu@\$HOST_IP:~/vm/ubuntu20
                    ssh -i hostkey ubuntu@\$HOST_IP -p 10022 "cd vm/ubuntu20 && ulimit -c unlimited && sudo ./run-qemu6-linux.sh > guest.log" &
                    echo $?
                '''

                sh 'sleep 480'
                sh '''
                    source host_ips.sh

                    ssh -i ./hostkey ubuntu@\$HOST_IP -p 10022 "cat vm/ubuntu20/guest.log" >/hyp/guest.log
                    ssh -i ./hostkey ubuntu@\$HOST_IP -p 10022 "dmesg" >/hyp/host-dmesg.log
                    ssh -i ./hostkey ubuntu@\$HOST_IP -p 10022 "sudo chmod 444 /var/lib/apport/coredump/* || true"
                    sshpass -p ubuntu scp -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -P10022 ubuntu@$HOST_IP:/var/lib/apport/coredump/* /hyp || true
                '''

                sh 'echo GUEST1_IP=$(grep ssh /hyp/guest.log | cut -d" " -f7|cut -d":" -f1) >> host_ips.sh'
                sh '''
                    source host_ips.sh
                    ssh -i ./hostkey ubuntu@\$HOST_IP -p 10022 ssh ubuntu@$GUEST1_IP -p 2000 "dmesg" > /hyp/guest1-dmesg.log || true
                    ssh -i ./hostkey ubuntu@\$HOST_IP -p 10022 ssh ubuntu@$GUEST1_IP -p 2000 "ps aux" > /hyp/guest1-ps.log || true
                    ssh -i ./hostkey ubuntu@\$HOST_IP -p 10022 ssh ubuntu@$GUEST1_IP -p 2000 "sudo shutdown now" || true
                '''
                sh 'sleep 30'
                sh '''
                    source host_ips.sh
                    ssh -i ./hostkey ubuntu@\$HOST_IP -p 10022 "ps aux"
                    ssh -i ./hostkey ubuntu@\$HOST_IP -p 10022 "sudo shutdown now" || true
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