FROM shn-docker-snapshots.artidev.shn.io:80/jenkins-slave:precise

RUN apt-get update
RUN apt-get install -y git python python-pip openjdk-7-jdk curl
RUN pip install sphinx
ENV JAVA_HOME "/usr/lib/jvm/java-7-openjdk-amd64"
ENV PATH "$PATH:$JAVA_HOME/bin"
EXPOSE 8080

RUN cd; git clone https://github.com/dswann5/glu
RUN cd ~/glu; git checkout ssl-harden
