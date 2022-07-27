###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_arcgis_server_rce_vuln.nasl 11982 2018-10-19 08:49:21Z mmartin $
#
# ArcGis Server 10.3.1 Remote Code Execution vulnerability
#
# Authors:
# Jan Philipp Schulte <jan.schulte@greenbone.net>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, https://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
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

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.113041");
  script_version("$Revision: 11982 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-19 10:49:21 +0200 (Fri, 19 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-10-25 13:47:48 +0200 (Wed, 25 Oct 2017)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("ArcGis Server 10.3.1 Remote Code Execution vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_arcgis_server_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("arcgis/installed");

  script_tag(name:"summary", value:"ArcGIS Server 10.3.1 is vulnerable to Remote Code Execution.");
  script_tag(name:"vuldetect", value:"The script checks if the vulnerable version is present on the host.");
  script_tag(name:"insight", value:"ArcGIS 10.3.1 sets useCodebaseOnly=false in Java, which creates a risk for Remote Code Execution.");
  script_tag(name:"impact", value:"Successful exploitation could allow the attacker to execute arbitrary code on the host.");
  script_tag(name:"affected", value:"ArcGIS Server version 10.3.1");
  script_tag(name:"solution", value:"Update to ArcGIS Server version 10.4.1");

  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2017/Oct/18");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2017/Oct/21");

  exit(0);
}

CPE = "cpe:/a:esri:arcgis";

include( "host_details.inc" );
include( "version_func.inc" );

if( !port = get_app_port( cpe: CPE ) ) exit( 0 );
if( !version = get_app_version( cpe: CPE, port: port ) ) exit( 0 );

if( version_is_less( version: version, test_version: "10.4.1" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "10.4.1" );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
