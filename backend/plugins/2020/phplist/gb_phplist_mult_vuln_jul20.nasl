# Copyright (C) 2020 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
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
  script_oid("1.3.6.1.4.1.25623.1.0.113719");
  script_version("2020-07-13T07:48:46+0000");
  script_tag(name:"last_modification", value:"2020-07-13 10:17:06 +0000 (Mon, 13 Jul 2020)");
  script_tag(name:"creation_date", value:"2020-07-13 07:24:03 +0000 (Mon, 13 Jul 2020)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2020-15072", "CVE-2020-15073");

  script_name("phpList < 3.5.5 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_phplist_detect.nasl");
  script_mandatory_keys("phplist/detected");

  script_tag(name:"summary", value:"phpList is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - An error-based SQL Injection vulnerability exists via the Import Administrators section. (CVE-2020-15072)

  - An XSS vulnerability occurs within the Import Administrators section
    via upload of an edited text document. This also affects the Subscriber Lists section. (CVE-2020-15073)");

  script_tag(name:"impact", value:"Successful exploitation would allow an authenticated attacker
  to inject arbitrary HTML and JavaScript into the site, read or modify sensitive information
  or execute arbitrary code on the target machine.");

  script_tag(name:"affected", value:"phpList through version 3.5.4.");

  script_tag(name:"solution", value:"Update to version 3.5.5.");

  script_xref(name:"URL", value:"https://www.phplist.org/newslist/phplist-3-5-5-release-notes/");

  exit(0);
}

CPE = "cpe:/a:phplist:phplist";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) ) exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version: version, test_version: "3.5.5" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "3.5.5", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
