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
  script_oid("1.3.6.1.4.1.25623.1.0.113359");
  script_version("2019-04-02T13:04:18+0000");
  script_tag(name:"last_modification", value:"2019-04-02 13:04:18 +0000 (Tue, 02 Apr 2019)");
  script_tag(name:"creation_date", value:"2019-04-02 12:07:31 +0000 (Tue, 02 Apr 2019)");
  script_tag(name:"cvss_base", value:"6.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2019-6970");

  script_name("Moodle CMS 3.5.x <= 3.5.3 SSRF vulnerability.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_moodle_cms_detect.nasl");
  script_mandatory_keys("moodle/detected");

  script_tag(name:"summary", value:"Moodle CMS is prone to an SSRF attack.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The edit_blog.php script allows a registered user to add external RSS feed resources.
  This feature could be abused as an SSRF attack vector by adding a malicious URL and
  TCP port in order to target the internal network or an internet hosted server,
  bypassing firewall rules, IP filtering and more.");
  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to perform GET requests while
  bypassing authentication mechanisms, potentially allowing for remote code execution.");
  script_tag(name:"affected", value:"Moodle CMS version 3.5.0 through 3.5.3.");
  script_tag(name:"solution", value:"Update to version 3.5.4.");

  script_xref(name:"URL", value:"https://www.excellium-services.com/cert-xlm-advisory/cve-2019-6970/");

  exit(0);
}

CPE = "cpe:/a:moodle:moodle";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! version = get_app_version( cpe: CPE, port: port ) ) exit( 0 );

if( version_in_range( version: version, test_version: "3.5.0", test_version2: "3.5.3" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "3.5.4" );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
