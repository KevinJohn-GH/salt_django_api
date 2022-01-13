# 生成的新镜像以centos7镜像为基础
FROM centos:7

# 使用root用户
USER root

# python2
RUN curl  https://bootstrap.pypa.io/pip/2.7/get-pip.py -o get-pip.py && \
    python2 get-pip.py && \
    yum install -y python2-devel

# 添加python3.6的环境变量
RUN yum install -y python36 && \
    yum groupinstall -y "Development tools" && \
    yum install -y mysql-devel && \
    yum install -y python3-devel

# 安装salt
RUN rpm --import https://repo.saltproject.io/py3/redhat/7/x86_64/3004/SALTSTACK-GPG-KEY.pub && \
	curl -fsSL https://repo.saltproject.io/py3/redhat/7/x86_64/3004.repo | tee /etc/yum.repos.d/salt.repo && \
	yum clean expire-cache && \
	yum install -y salt-master && \
	yum install -y salt-minion && \
	yum install -y salt-ssh && \
	yum install -y salt-syndic && \
	yum install -y salt-cloud && \
	yum install -y salt-api

# 安装openssh-server
RUN yum -y install openssh-server && \
    ssh-keygen -t dsa -f /etc/ssh/ssh_host_dsa_key && \
    ssh-keygen -t rsa -f /etc/ssh/ssh_host_rsa_key

# 变更root密码
RUN echo "root:12345"|chpasswd

# 开放22端口
EXPOSE 22
EXPOSE 8080

# 运行脚本，启动sshd服务
CMD    ["/usr/sbin/sshd", "-D"]