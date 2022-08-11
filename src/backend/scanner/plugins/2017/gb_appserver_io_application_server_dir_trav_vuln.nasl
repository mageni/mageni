###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_appserver_io_application_server_dir_trav_vuln.nasl 11936 2018-10-17 09:05:37Z mmartin $
#
# appserver.io Application Server Directory Traversal Vulnerability
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:appserver:io";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811268");
  script_version("$Revision: 11936 $");
  script_cve_id("CVE-2015-1847");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-17 11:05:37 +0200 (Wed, 17 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-08-02 11:04:18 +0530 (Wed, 02 Aug 2017)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("appserver.io Application Server Directory Traversal Vulnerability");

  script_tag(name:"summary", value:"This host is installed with appserver.io
  application server and is prone to directory traversal vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to error in the bundled
  webserver's HTTP parsing library, URI as coming from a web client was not
  normalized correctly.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to traversal movement through the file system of the host without
  the restriction of the configured document root. This allowed for access of
  otherwise inaccessible files through specially crafted HTTP requests.");

  script_tag(name:"affected", value:"appserver.io Application Server before
  version 1.0.3");

  script_tag(name:"solution", value:"Upgrade to appserver.io version 1.0.3 or
  later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://appserver.io/security/2015/03/31/traversal-directory-vulnerability-in-webserver.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("gb_appserver_io_application_server_detect.nasl");
  script_mandatory_keys("appserver/io/ApplicationServer/ver");
  script_require_ports("Services/www", 9080);
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!appPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!appVer = get_app_version(cpe:CPE, port:appPort)){
  exit(0);
}

if(version_is_less(version:appVer, test_version:"1.0.3"))
{
  report = report_fixed_ver(installed_version:appVer, fixed_version:"1.0.3");
  security_message(data:report, port:appPort);
  exit(0);
}
exit(0);
