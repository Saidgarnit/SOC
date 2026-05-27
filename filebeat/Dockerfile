FROM docker.elastic.co/beats/filebeat:8.13.0
USER root
COPY --chown=root:root filebeat.yml /usr/share/filebeat/filebeat.yml
COPY modules.d/*.yml /usr/share/filebeat/modules.d/
RUN chmod go-w /usr/share/filebeat/filebeat.yml
