FROM oraclelinux:8.4
RUN yum update -y && \
    yum install -y bind bind-utils bind-libs bind-chroot
RUN    mkdir -p /var/named/masters
RUN    chmod u=rwx,g=rx /var/named/masters
RUN    chown named:named /var/named/masters

EXPOSE 53

#CMD ping 127.0.0.1

#CMD ["bash"]

CMD ["/usr/sbin/named", "-c", "/etc/named.conf", "-g", "-u", "named"]
