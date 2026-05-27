FROM docker.elastic.co/logstash/logstash:8.13.0
COPY pipeline/logstash.conf /usr/share/logstash/pipeline/logstash.conf
COPY geoip/GeoLite2-City.mmdb /usr/share/logstash/geoip/GeoLite2-City.mmdb
RUN /usr/share/logstash/bin/logstash-plugin install logstash-filter-http
