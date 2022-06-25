###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_invision_sqli_vuln.nasl 12120 2018-10-26 11:13:20Z mmartin $
#
# Invision Power Board 3.4.5 SQLi Vulnerability
#
# Authors:
# Jan Philipp Schulte <jan.schulte@greenbone.net>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, https://www.greenbone.net
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

CPE = "cpe:/a:invision_power_services:invision_power_board";

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.113143");
  script_version("$Revision: 12120 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 13:13:20 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2018-03-22 12:47:45 +0100 (Thu, 22 Mar 2018)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2014-4928");

  script_name("Invision Power Board 3.4.5 SQLi Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("invision_power_board_detect.nasl");
  script_mandatory_keys("invision_power_board/installed");

  script_tag(name:"summary", value:"Invision Power Board is prone to an SQL Injection Vulnerability.");

  script_tag(name:"vuldetect", value:"The script checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to insufficient sanitation of the 'cld' parameter.");

  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to execute arbitrary SQL
commands on the target system. This would result in effects ranging from information disclosure to gaining
complete access over the target system.");

  script_tag(name:"affected", value:"Invision Power Board through version 3.4.5.");

  script_tag(name:"solution", value:"Update to version 3.4.6.");

  script_xref(name:"URL", value:"http://dringen.blogspot.de/2014/07/invision-power-board-blind-sql.html");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! version = get_app_version( cpe: CPE, port: port ) ) exit( 0 );

if( version_is_less( version: version, test_version: "3.4.6" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "3.4.6" );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
