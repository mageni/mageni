###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_discourse_stored_xss_vuln.nasl 12116 2018-10-26 10:01:35Z mmartin $
#
# Discourse < 2.0.0 beta6 Stored XSS Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.112352");
  script_version("$Revision: 12116 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 12:01:35 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2018-08-08 09:46:25 +0200 (Wed, 08 Aug 2018)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");


  script_name("Discourse < 2.0.0 beta6 Stored XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_discourse_detect.nasl");
  script_mandatory_keys("discourse/detected");

  script_tag(name:"summary", value:"This host is running Discourse and is prone to a stored cross-site scripting (XSS) vulnerability.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to steal cookies, passwords or to run arbitrary code on the victim's browser.");
  script_tag(name:"affected", value:"Discourse before version 2.0.0 beta6.");
  script_tag(name:"solution", value:"Update Discourse to version 2.0.0 beta6 or later.");

  script_xref(name:"URL", value:"https://hackerone.com/reports/333507");
  script_xref(name:"URL", value:"https://github.com/discourse/discourse/commit/4fb41663b3c7071dc1ef7d92eb3e5a6516dfe3b5");

  exit(0);
}

CPE = "cpe:/a:discourse:discourse";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! version = get_app_version( cpe: CPE, port: port ) ) exit( 0 );

if( version_is_less( version: version, test_version: "2.0.0.beta6" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "2.0.0.beta6" );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
