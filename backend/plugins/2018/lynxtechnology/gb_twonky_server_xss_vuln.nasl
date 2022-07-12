###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_twonky_server_xss_vuln.nasl 12120 2018-10-26 11:13:20Z mmartin $
#
# Twonky Server < 8.5.1 XSS Vulnerability
#
# Authors:
# Adrian Steins <adrian.steins@greenbone.net>
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
  script_oid("1.3.6.1.4.1.25623.1.0.112301");
  script_version("$Revision: 12120 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 13:13:20 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2018-06-11 13:06:00 +0200 (Mon, 11 Jun 2018)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2018-9177", "CVE-2018-9182");

  script_name("Twonky Server < 8.5.1 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_twonky_server_detect.nasl");
  script_mandatory_keys("twonky_server/installed");

  script_tag(name:"summary", value:"Twonky Server is prone to cross-site scripting vulnerabilities.");
  script_tag(name:"vuldetect", value:"The script checks if a vulnerable version is present on the target system.");
  script_tag(name:"insight", value:"Following vulnerabilities exist:

  - XSS via a folder name on the Shared Folders screen.

  - XSS via a modified 'language' parameter in the Language section.");
  script_tag(name:"affected", value:"Twonky Server through 8.5.");
  script_tag(name:"solution", value:"Upgrade to version 8.5.1 or later.");

  script_xref(name:"URL", value:"https://gist.github.com/prafagr/bd641fcfe71661065e659672c737173b");
  script_xref(name:"URL", value:"https://gist.github.com/priyanksethi/08fb93341cf7e61344aad5c4fee3aa9b");

  exit(0);
}

CPE = "cpe:/a:twonky:twonky_server";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! version = get_app_version( cpe: CPE, port: port ) ) exit( 0 );

if( version_is_less( version: version, test_version: "8.5.1" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "8.5.1" );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
