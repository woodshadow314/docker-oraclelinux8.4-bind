FROM oraclelinux:8.4
RUN yum update -y && \
    yum install -y bind bind-utils bind-libs bind-chroot

EXPOSE 53

CMD ping 127.0.0.1

#CMD ["bash"]

#CMD ["named", "-c", "/etc/bind/named.conf", "-g", "-u", "named"]