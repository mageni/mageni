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
  script_oid("1.3.6.1.4.1.25623.1.0.112616");
  script_version("2019-08-05T12:23:26+0000");
  script_tag(name:"last_modification", value:"2019-08-05 12:23:26 +0000 (Mon, 05 Aug 2019)");
  script_tag(name:"creation_date", value:"2019-08-05 12:11:11 +0000 (Mon, 05 Aug 2019)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"executable_version_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2019-14232", "CVE-2019-14233", "CVE-2019-14234", "CVE-2019-14235");

  script_name("Django 1.11.x < 1.11.23, 2.1.x < 2.1.11, 2.2.x < 2.2.4 Multiple Vulnerabilities (Linux)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_django_detect_lin.nasl");
  script_mandatory_keys("Django/Linux/Ver");

  script_tag(name:"summary", value:"Django is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2019-14232: Denial-of-service possibility in django.utils.text.Truncator

  - CVE-2019-14233: Denial-of-service possibility in strip_tags()

  - CVE-2019-14234: SQL injection possibility in key and index lookups for JSONField/HStoreField

  - CVE-2019-14235: Potential memory exhaustion in django.utils.encoding.uri_to_iri().");

  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to crash the
  affected system or inject and execute malicious SQL queries.");

  script_tag(name:"affected", value:"Django versions 1.11.0 through 1.11.22, 2.1.0 through 2.1.10 and 2.2.0 through 2.2.3.");

  script_tag(name:"solution", value:"Update to version 1.11.23, 2.1.11 or 2.2.4 respectively.");

  script_xref(name:"URL", value:"https://groups.google.com/forum/#!topic/django-announce/jIoju2-KLDs");
  script_xref(name:"URL", value:"https://www.djangoproject.com/weblog/2019/aug/01/security-releases/");

  exit(0);
}

CPE = "cpe:/a:django_project:django";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE ) ) exit( 0 );
version = infos["version"];
location = infos["location"];

if( version_in_range( version: version, test_version: "1.11.0", test_version2: "1.11.22" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "1.11.23", install_path: location );
  security_message( data: report, port: 0 );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "2.1.0", test_version2: "2.1.10" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "2.1.11", install_path: location );
  security_message( data: report, port: 0 );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "2.2.0", test_version2: "2.2.3" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "2.2.4", install_path: location );
  security_message( data: report, port: 0 );
  exit( 0 );
}

exit( 99 );
