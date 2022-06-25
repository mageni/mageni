###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_monsta_ftp_mult_vuln.nasl 11872 2018-10-12 11:22:41Z cfischer $
#
# Monsta FTP Multiple Vulnerabilities
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

CPE = "cpe:/a:monsta:ftp";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806050");
  script_version("$Revision: 11872 $");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 13:22:41 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-09-15 09:23:14 +0530 (Tue, 15 Sep 2015)");
  script_tag(name:"qod_type", value:"remote_vul");
  script_name("Monsta FTP Multiple Vulnerabilities");

  script_tag(name:"summary", value:"This host is installed with Monsta FTP and
  is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send a crafted request via HTTP GET and
  check whether it is able to read cookie or not.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - Insufficient sanitization of user supplied input by index.php script.

  - No CSRF token exists when making some POST requests.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute arbitrary script code in a user's browser session within
  the trust relationship between their browser and allowing arbitrary deletion
  of files on the monstaftp server.");

  script_tag(name:"affected", value:"Monsta FTP version 1.6.2.");

  script_tag(name:"solution", value:"Upgrade to Monsta FTP version 1.6.3
  or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/38148");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_monsta_ftp_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("Monsta-FTP-master/Installed");

  script_xref(name:"URL", value:"http://www.monstaftp.com");
  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

if(!http_port = get_app_port(cpe:CPE)){
  exit(0);
}

if(!dir = get_app_location(cpe:CPE, port:http_port)){
  exit(0);
}

url = dir + '/?openFolder="/><script>alert(document.cookie)</script>';

if(http_vuln_check(port:http_port, url:url, check_header:TRUE,
   pattern:"alert\(document.cookie\)",
   extra_check:make_list("<title>Monsta FTP", 'value="Login"')))
{
  report = report_vuln_url( port:http_port, url:url );
  security_message(port:http_port, data:report);
  exit(0);
}

exit(99);