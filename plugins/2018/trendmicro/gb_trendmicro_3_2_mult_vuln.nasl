###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_trendmicro_3_2_mult_vuln.nasl 12120 2018-10-26 11:13:20Z mmartin $
#
# Trend Micro Smart Protection Server 3.2 Multiple Vulnerabilities
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

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.113088");
  script_version("$Revision: 12120 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 13:13:20 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2018-01-23 11:11:11 +0100 (Tue, 23 Jan 2018)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2017-11398", "CVE-2017-14094", "CVE-2017-14095", "CVE-2017-14096", "CVE-2017-14097");
  script_bugtraq_id(102275);

  script_name("Trend Micro Smart Protection Server 3.2 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_trendmicro_smart_protection_server_detect.nasl");
  script_require_ports("Services/www", 4343);
  script_mandatory_keys("trendmicro/SPS/Installed");

  script_tag(name:"summary", value:"Trend Micro Smart Protection Server through version 3.2 is prone to multiple vulnerabilities.");
  script_tag(name:"vuldetect", value:"The script checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Trend Micro Smart Protection Server 3.2 is prone to

  3 Remote Code Execution (RCE) vulnerabilities

  A Session Hijacking Vulnerability

  An Information Disclosure Vulnerability.");
  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to access sensitive information or even get control of the target host.");
  script_tag(name:"affected", value:"Trend Micro Smart Protection Server through version 3.2");
  script_tag(name:"solution", value:"Update to version 3.3");

  script_xref(name:"URL", value:"https://success.trendmicro.com/solution/1118992");
  script_xref(name:"URL", value:"https://www.coresecurity.com/advisories/trend-micro-smart-protection-server-multiple-vulnerabilities");

  exit(0);
}

CPE = "cpe:/a:trendmicro:smart_protection_server";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! version = get_app_version( cpe: CPE, port: port ) ) exit( 0 );

if( version_is_less_equal( version: version, test_version: "3.2" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "3.3" );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
