#/usr/bin/python3
#-*- coding: utf-8 -*-
#This is to get crt for your host from letsencryt
#Version:
#Author: Elival
#Feel free to contact me  if you have any issues or advice at https://github.com/Elival

import os
import logging

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
stream_handler = logging.StreamHandler()
file_handler = logging.FileHandler('auto_crt.log')
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
file_handler.setFormatter(formatter)
logger.addHandler(stream_handler)
logger.addHandler(file_handler)

def do_bash(bash_commands):
	for doLog, command in bash_commands:
		logger.info(doLog)
		os.system(command)

def do_check():
	if not os.path.isfile('/etc/letsencrypt/intermediate.pem'):
		os.system("wget -O - https://letsencrypt.org/certs/lets-encrypt-x3-cross-signed.pem > intermediate.pem")
	if not os.path.isfile('/etc/letsencrypt/acme_tiny.py'):
		os.system("wget https://raw.githubusercontent.com/diafygi/acme-tiny/master/acme_tiny.py")

def gen_account():
	bash_commands = ('Generating letsencryt account for this domain', 'openssl genrsa 4096 > {}.account.key'.format(domain))
	do_bash(bash_commands)

def gen_csr():
	bash_commands = (
		'Generating host key', "openssl ecparam -genkey -name secp384r1 | openssl ec -out {host}.key".format(host)
		'Generating host csr', '''openssl req -new -sha256 -key {host}.key -subj "/" -reqexts SAN -config <(cat /etc/ssl/openssl.cnf <(printf "[SAN]\nsubjectAltName=DNS:{host}")) > {host}.csr'''.format(host)
		)
	do_bash(bash_commands)

def apply_crt():
    
    http_conf = '''
    server {{
      listen 80;
      server_name {};

      #优先配置证书 
      location ^~ /.well-known/acme-challenge/ {{
        alias /etc/letsencrypt/challenges/;
        try_files $uri =404;
      }}

      #文件重定向
      location / {{
        rewrite ^(.*) https://$server_name$1 permanent;
      }}
     }}'''.format(host)

     https_conf = '''
    server {{
      listen 443;
      server_name {0};

      ssl on;
      ssl_certificate     /etc/letsencrypt/{0}.pem;
      ssl_certificate_key /etc/letsencrypt/{0}.key;

      #Wordpress 配置
      root   /var/www/html/{};
      index  index.html index.php;

      #php配置
      location ~ .php$ {{
      fastcgi_pass unix:/var/run/php70-php-fpm.sock;
      #fastcgi_pass 127.0.0.1:9000;
      fastcgi_index index.php;
      include fastcgi_params;
      fastcgi_param   SCRIPT_FILENAME    $document_root$fastcgi_script_name;

      #扩展接口
      }}
    }}'''.format(host)

	nginx_conf = '/etc/nginx/conf.d/{}'.format(host)
	with open(nginx_conf, 'w') as f:
		logger.info("Generating nginx conf to apply for the host")
		f.write(http_conf)
		try:
			bash_commands = ('Applying crt from letsencrypt', 'python acme_tiny.py --account-key {domain}.account.key --csr {host}.csr --acme-dir /challenges/ > {host}.crt').format(host))
            do_bash(bash_commands)
        except Exception:
        	logger.exception("Something went wrong.You can check the log in /var/log/auto_crt.log for further help")
        else:
        	logger.info('Succeed. Generating full nginx conf for the host')
        	with open(nginx_conf, 'a') as f:
        		f.write(https_conf)

def gen_pem():
	bash_commands = ('Generating pem', 'cat intermediate.pem {host}.crt > {host}.pem'.format(host))
	do_bash(bash_commands)

def main():
	host = ''
	domain = ''


	import argparse
	parser = argparse.ArgumentParser(description="")
	parser.add_argument('host', help="This is your host name to get cert.")
	parser.add_argument('num', type=int, default=2, help='This describe how many nunmbers your domain have in the host')
	args = parser.parse_args()

	host = args.host
	host_info_list = host.split('.')
	for i in sorted(range(args.num), reverse=True):
		domain = domain + host_info_list[-i] + '.'

	os.system("cd /etc/letsencrypt")

	do_check()

	if not os.path.isfile('/etc/letsencrypt/{domain}.account.key'.format(domain)):
		gen_account()

	if not os.path.isfile('/etc/letsencrypt/{host}.csr'.format(host)):
		gen_csr()

	apply_crt()

	gen_pem()

if __name__ == '__main__':
	main()
    









