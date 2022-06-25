###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_otrs_info_disc_vuln.nasl 12120 2018-10-26 11:13:20Z mmartin $
#
# OTRS 6.0.x < 6.0.7 Information Disclosure Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.112299");
  script_version("$Revision: 12120 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 13:13:20 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2018-06-07 12:16:22 +0200 (Thu, 07 Jun 2018)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2018-10198");

  script_name("OTRS 6.0.x < 6.0.7 Information Disclosure Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_otrs_detect.nasl");
  script_mandatory_keys("OTRS/installed");

  script_tag(name:"summary", value:"OTRS is prone to an Information Disclosure vulnerability.");
  script_tag(name:"vuldetect", value:"The script checks if a vulnerable version is present on the target host.");
  script_tag(name:"impact", value:"An attacker who is logged into OTRS as a customer can use the ticket overview screen to disclose internal article information of their customer tickets.");
  script_tag(name:"affected", value:"OTRS 6.0.x through 6.0.6.");
  script_tag(name:"solution", value:"Update to ORTS 6.0.7.");

  script_xref(name:"URL", value:"https://community.otrs.com/security-advisory-2018-01-security-update-for-otrs-framework/");

  exit(0);
}

CPE = "cpe:/a:otrs:otrs";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! version = get_app_version( cpe: CPE, port: port ) ) exit( 0 );

if( version_in_range( version: version, test_version: "6.0.0", test_version2: "6.0.6" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "6.0.7" );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
