###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_zikula_jcss_dir_trav_vuln.nasl 14168 2019-03-14 08:10:09Z cfischer $
#
# Zikula 'jcss.php' Directory Traversal Vulnerability
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH
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

CPE = "cpe:/a:zikula:zikula_application_framework";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809746");
  script_version("$Revision: 14168 $");
  script_cve_id("CVE-2016-9835");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2019-03-14 09:10:09 +0100 (Thu, 14 Mar 2019) $");
  script_tag(name:"creation_date", value:"2016-12-09 18:25:21 +0530 (Fri, 09 Dec 2016)");
  script_name("Zikula 'jcss.php' Directory Traversal Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_zikula_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("zikula/detected", "Host/runs_windows");
  script_require_ports("Services/www", 80);

  script_xref(name:"URL", value:"https://github.com/zikula/core/issues/3237");
  script_xref(name:"URL", value:"https://github.com/zikula/core/blob/1.3/CHANGELOG-1.3.md");
  script_xref(name:"URL", value:"https://github.com/zikula/core/blob/1.4/CHANGELOG-1.4.md");

  script_tag(name:"summary", value:"This host is installed with Zikula and
  is prone to directory traversal vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted HTTP GET request
  and determine based on response if it is vulnerable to directory traversal.");

  script_tag(name:"insight", value:"The flaw exists due to insufficient
  sanitization of input passed via 'f' parameter to 'jcss.php' script.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to launch a PHP object injection by uploading a serialized file.");

  script_tag(name:"affected", value:"Zikula 1.3.x before 1.3.11 and 1.4.x
  before 1.4.4 on Windows.");

  script_tag(name:"solution", value:"Upgrade to Zikula 1.3.11 or 1.4.4 or later.");

  script_tag(name:"qod_type", value:"remote_analysis");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE, service:"www"))
  exit(0);

if(!dir = get_app_location(cpe:CPE, port:port))
  exit(0);

if(dir == "/")
  dir = "";

url = dir + "/jcss.php?f=..\..\..\..\..\jcss.php";

req = http_get(item:url, port:port);
res = http_keepalive_send_recv(port:port, data:req);

# nb: For patched version response is  "Requested file not readable" and non patched "Corrupted file"
if(res =~ "^HTTP/1\.[01] 500" && "ERROR: Corrupted file" >< res && "ERROR: Requested file not readable" >!< res) {
  report = report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);