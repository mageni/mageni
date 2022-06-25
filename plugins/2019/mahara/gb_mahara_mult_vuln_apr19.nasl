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

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.112572");
  script_version("2019-05-08T11:26:09+0000");
  script_tag(name:"last_modification", value:"2019-05-08 11:26:09 +0000 (Wed, 08 May 2019)");
  script_tag(name:"creation_date", value:"2019-05-08 11:04:00 +0000 (Wed, 08 May 2019)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2019-9708", "CVE-2019-9709");

  script_name("Mahara 17.10 < 17.10.8, 18.04 < 18.04.4, 18.10 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_mahara_detect.nasl");
  script_mandatory_keys("mahara/detected");
  script_require_ports("Services/www", 80);

  script_tag(name:"summary", value:"This host is running Mahara and is prone to multiple vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Mahara is prone to the following vulnerabilities:

  - A site administrator can suspend the system user (root), causing all users to be locked out
  from the system. (CVE-2019-9708)

  - The collection title is vulnerable to Cross Site Scripting (XSS) due to not escaping it when
  viewing the collection's SmartEvidence overview page (if that feature is turned on).
  This can be exploited by any logged-in user. (CVE-2019-9709)");
  script_tag(name:"affected", value:"Mahara 17.10 before 17.10.8, 18.04 before 18.04.4, and 18.10 before 18.10.1.");
  script_tag(name:"solution", value:"Update to Mahara 17.10.8, 18.04.4 or 18.10.1 respectively.");

  script_xref(name:"URL", value:"https://bugs.launchpad.net/mahara/+bug/1819547");
  script_xref(name:"URL", value:"https://mahara.org/interaction/forum/topic.php?id=8446");
  script_xref(name:"URL", value:"https://bugs.launchpad.net/mahara/+bug/1817221");
  script_xref(name:"URL", value:"https://mahara.org/interaction/forum/topic.php?id=8445");

  exit(0);
}

CPE = "cpe:/a:mahara:mahara";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! version = get_app_version( cpe: CPE, port: port ) ) exit( 0 );

if( version_in_range( version: version, test_version: "17.10", test_version2: "17.10.7" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "17.10.8" );
  security_message( data: report, port: port );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "18.04", test_version2: "18.04.3" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "18.04.4" );
  security_message( data: report, port: port );
  exit( 0 );
}

if( version_is_equal( version: version, test_version: "18.10" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "18.10.1" );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
