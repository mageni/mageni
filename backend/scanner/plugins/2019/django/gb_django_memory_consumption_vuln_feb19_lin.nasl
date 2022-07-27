# Copyright (C) 2019 Greenbone Networks GmbH
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.113344");
  script_version("$Revision: 13986 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-05 08:32:41 +0100 (Tue, 05 Mar 2019) $");
  script_tag(name:"creation_date", value:"2019-02-26 14:37:01 +0200 (Tue, 26 Feb 2019)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_tag(name:"qod", value:"30");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2019-6975");
  script_bugtraq_id(106964);

  script_name("Django < 2.16 Uncontrolled Memory Consumption Vulnerability (Linux)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_django_detect_lin.nasl");
  script_mandatory_keys("Django/Linux/Ver");

  script_tag(name:"summary", value:"Django is prone to an uncontrolled memory consumption vulnerability.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"If django.utils.numberformat.format() received a Decimal with a large number
  of digits or a large exponent, it could lead to significant memory usage
  due to a call to .format().");
  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to exhaust the target system's
  resources and crash the affected and other applications.");
  script_tag(name:"affected", value:"Django through version 1.11.18, version 2.0.0 through 2.0.10 and 2.1.0 through 2.1.5.");
  script_tag(name:"solution", value:"Update to version 1.11.19, 2.0.11 or 2.1.6 respectively.");

  script_xref(name:"URL", value:"https://www.djangoproject.com/weblog/2019/feb/11/security-releases/");

  exit(0);
}

CPE = "cpe:/a:django_project:django";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! version = get_app_version( cpe: CPE, port: port ) ) exit( 0 );

if( version_is_less( version: version, test_version: "1.11.19" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "1.11.19" );
  security_message( data: report, port: port );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "2.0.0", test_version2: "2.0.10" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "2.0.11" );
  security_message( data: report, port: port );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "2.1.0", test_version2: "2.1.5" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "2.1.6" );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );