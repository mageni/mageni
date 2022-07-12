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
  script_oid("1.3.6.1.4.1.25623.1.0.113361");
  script_version("2019-04-02T11:18:03+0000");
  script_tag(name:"last_modification", value:"2019-04-02 11:18:03 +0000 (Tue, 02 Apr 2019)");
  script_tag(name:"creation_date", value:"2019-04-02 12:30:54 +0000 (Tue, 02 Apr 2019)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2019-3809");

  script_name("Moodle CMS <= 3.1.15 SSRF Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_moodle_cms_detect.nasl");
  script_mandatory_keys("moodle/detected");

  script_tag(name:"summary", value:"Moodle CMS is prone to an SSRF vulnerability.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The mybackpack functionality allows setting the URL of badges,
  when it should be restricted to the Mozilla Open Badges backpack URL.");
  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to make GET requests
  while bypassing authentication, potentially leading to remote code execution.");
  script_tag(name:"affected", value:"Moodle CMS through version 3.1.15.");
  script_tag(name:"solution", value:"Update to version 3.1.16.");

  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=381229#p1536766");

  exit(0);
}

CPE = "cpe:/a:moodle:moodle";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! version = get_app_version( cpe: CPE, port: port ) ) exit( 0 );

if( version_is_less( version: version, test_version: "3.1.16" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "3.1.16" );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );