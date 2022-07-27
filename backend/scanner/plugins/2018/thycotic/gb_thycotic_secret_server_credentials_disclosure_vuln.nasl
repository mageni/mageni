###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_thycotic_secret_server_credentials_disclosure_vuln.nasl 12025 2018-10-23 08:16:52Z mmartin $
#
# Thycotic Secret Server Credentials Disclosure Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.113153");
  script_version("$Revision: 12025 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-23 10:16:52 +0200 (Tue, 23 Oct 2018) $");
  script_tag(name:"creation_date", value:"2018-04-10 16:25:00 +0200 (Tue, 10 Apr 2018)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2014-4861");

  script_name("Thycotic Secret Server Credentials Disclosure Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_thycotic_secret_server_detect.nasl");
  script_mandatory_keys("thycotic_secretserver/installed");

  script_tag(name:"summary", value:"The Remote Desktop Launcher in Thycotic Secret Server does not properly cleanup a temporary file
  that contains an encrypted password once a session has ended.");
  script_tag(name:"vuldetect", value:"The script checks if a vulnerable version is present on the target host.");
  script_tag(name:"impact", value:"If using the launcher to start a remote desktop session,
  the authentication credential remains accessible to users who initiated the connection, even when their launcher session is over.");
  script_tag(name:"affected", value:"Thycotic Secret Server versions between 7.5.000000 and 8.6.000009");
  script_tag(name:"solution", value:"Update to version 8.6.000010");

  script_xref(name:"URL", value:"https://thycotic.com/products/secret-server/resources/advisories/cve-2014-4861/");

  exit(0);
}

CPE = "cpe:/a:thycotic:secret_server";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! version = get_app_version( cpe: CPE, port: port ) ) exit( 0 );

if( version_in_range( version: version, test_version: "7.5.000000", test_version2: "8.6.000009" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "8.6.000010" );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
