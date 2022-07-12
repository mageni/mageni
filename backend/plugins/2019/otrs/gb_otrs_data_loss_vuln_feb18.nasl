# Copyright (C) 2019 Greenbone Networks GmbH, https://www.greenbone.net
#
# SPDX-License-Identifier: GPL-2.0-or-later
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
  script_oid("1.3.6.1.4.1.25623.1.0.112538");
  script_version("$Revision: 14313 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-19 11:54:46 +0100 (Tue, 19 Mar 2019) $");
  script_tag(name:"creation_date", value:"2019-03-19 09:51:12 +0100 (Tue, 19 Mar 2019)");
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:P/A:P");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2018-20800");

  script_name("OTRS 6.0.13, 5.0.31 Data Loss Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_otrs_detect.nasl");
  script_mandatory_keys("OTRS/installed");

  script_tag(name:"summary", value:"OTRS is prone to a data loss vulnerability.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"impact", value:"Users updating to OTRS 6.0.13 (also patchlevel updates) or 5.0.31 (only major updates)
  will experience data loss in their agent preferences table.");
  script_tag(name:"affected", value:"OTRS version 6.0.13 and 5.0.31.");
  script_tag(name:"solution", value:"Update to OTRS version 6.0.14 or 5.0.32 respectively.


  NOTE: If the system has been affected by the data loss, users can restore the user_preferences table from their backup and
  delete the OTRS cache via otrs/bin/otrs.Console.pl Maint::Delete::Cache. If the LDAP Sync module is used,
  it is sufficient to log in to the system again.");

  script_xref(name:"URL", value:"https://community.otrs.com/security-advisory-2018-10-security-update-for-otrs-framework/");

  exit(0);
}

CPE = "cpe:/a:otrs:otrs";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! version = get_app_version( cpe: CPE, port: port ) ) exit( 0 );

if( version_in_range( version: version, test_version: "5.0.0", test_version2: "5.0.31" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "5.0.32" );
  security_message( data: report, port: port );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "6.0.0", test_version2: "6.0.13" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "6.0.14" );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
