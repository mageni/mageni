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
  script_oid("1.3.6.1.4.1.25623.1.0.113410");
  script_version("2019-06-17T13:10:14+0000");
  script_tag(name:"last_modification", value:"2019-06-17 13:10:14 +0000 (Mon, 17 Jun 2019)");
  script_tag(name:"creation_date", value:"2019-06-17 11:33:50 +0000 (Mon, 17 Jun 2019)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2019-12830", "CVE-2019-12831");

  script_name("MyBB < 1.8.21 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("sw_mybb_detect.nasl");
  script_mandatory_keys("MyBB/installed");

  script_tag(name:"summary", value:"MyBB is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Following vulnerabilities exist:

  - An attacker can exploit a parsing flaw in the Private Message / Post renderer
  that leads to [video] BBCode persistent XSS to take over any forum account,
  aka a nested video MyCode issue. (CVE-2019-12830)

  - An attacker can abuse a default behavior of MySQL on many systems
  (that leads to truncation of strings that are too long for a database column)
  to create a PHP shell in the cache directory of a targeted forum via a crafted XML import,
  aka theme import stylesheet name RCE. (CVE-2019-12831)

  - Find Orphaned Attachments reflected XSS

  - Post edit reflected XSS

  - Private Messaging folders SQL injection

  - Potential phar deserialization through Upload Path");

  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to execute arbitrary code on the target machine.");

  script_tag(name:"affected", value:"MyBB through version 1.8.20.");

  script_tag(name:"solution", value:"Update to version 1.8.21.");

  script_xref(name:"URL", value:"https://blog.mybb.com/2019/06/10/mybb-1-8-21-released-security-maintenance-release/");
  script_xref(name:"URL", value:"https://blog.ripstech.com/2019/mybb-stored-xss-to-rce/");

  exit(0);
}

CPE = "cpe:/a:mybb:mybb";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) ) exit( 0 );
version = infos["version"];
location = infos["location"];

if( version_is_less( version: version, test_version: "1.8.21" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "1.8.21", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
