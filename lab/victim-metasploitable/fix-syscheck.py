import re
path = '/var/ossec/etc/ossec.conf'
conf = open(path).read()
conf = re.sub(
    r'([\s\S]*?)no()',
    r'\1yes\2',
    conf
)
open(path, 'w').write(conf)
print('syscheck disabled OK')
