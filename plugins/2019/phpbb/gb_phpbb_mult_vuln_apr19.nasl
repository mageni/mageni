# Copyright (C) 2019 Greenbone Networks GmbH
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

CPE = "cpe:/a:phpbb:phpbb";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112571");
  script_version("2019-05-06T08:35:31+0000");
  script_tag(name:"last_modification", value:"2019-05-06 08:35:31 +0000 (Mon, 06 May 2019)");
  script_tag(name:"creation_date", value:"2019-05-06 10:27:11 +0200 (Mon, 06 May 2019)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2019-9826", "CVE-2019-11767");
  script_name("phpBB < 3.2.6 Multiple Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("phpbb_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("phpBB/installed");

  script_tag(name:"summary", value:"phpBB is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - Successful exploitation generates a slow SQL query which causes the
  database engine used by phpBB to consume all available CPU resources.
  Depending upon the database engine, users will also be completely unable
  to create or modify posts due to locks on the search index tables. The
  slowness of the query depends on the size of the search_wordlist and
  search_wordmatch tables (CVE-2019-9826).

  - Server side request forgery (SSRF) allows checking for the existence of files and services on the local
  network of the host through the remote avatar upload function (CVE-2019-11767).");

  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to trigger
  a denial of service attack via the keywords URL parameter of search.php and to check for the
  existence of files and services.");

  script_tag(name:"affected", value:"phpBB versions before 3.2.6.");

  script_tag(name:"solution", value:"Update to version 3.2.6 or later.");

  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2019/04/29/3");
  script_xref(name:"URL", value:"https://www.phpbb.com/community/viewtopic.php?f=14&t=2509941");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) )
  exit( 0 );

vers = infos['version'];
path = infos['location'];

if( version_is_less( version:vers, test_version:"3.2.6" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"3.2.6", install_path:path );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
