# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.113623");
  script_version("2020-01-13T13:59:49+0000");
  script_tag(name:"last_modification", value:"2020-01-13 13:59:49 +0000 (Mon, 13 Jan 2020)");
  script_tag(name:"creation_date", value:"2020-01-13 13:51:16 +0000 (Mon, 13 Jan 2020)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:P/A:N");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2019-20375", "CVE-2019-20376");

  script_name("ELOG <= 3.1.4 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_elog_detect.nasl");
  script_mandatory_keys("ELOG/detected");

  script_tag(name:"summary", value:"ELOG is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - A cross-site scripting (XSS) vulnerability allows remote attackers
    to inject arbitrary web script or HTML into the site via
    a crafted SVG document to elogd.c.

  - A cross-site scripting (XSS) vulnerability allows remote attackers
    to inject arbitrary web script or HTML into the site via
    the value parameter in a localization (loc) command to elogd.c.");

  script_tag(name:"affected", value:"ELOG through version 3.1.4.");

  script_tag(name:"solution", value:"Update to the latest version.");

  script_xref(name:"URL", value:"https://bitbucket.org/ritt/elog/commits/eefdabb714f26192f585083ef96c8413e459a1d1");
  script_xref(name:"URL", value:"https://bitbucket.org/ritt/elog/commits/993bed4923c88593cc6b1186e0d1b9564994a25a");

  exit(0);
}

CPE = "cpe:/a:stefan_ritt:elog_web_logbook";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) ) exit( 0 );

version = infos["version"];
location = infos["location"];

# e.g. 3.1.4.e64[...] would not be detected with just a less_equal()
if( version_is_less( version: version, test_version: "3.1.4" ) || version =~ '^3.1.4($|\\.)') {
  report = report_fixed_ver( installed_version: version, fixed_version: "Update to the latest version.", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
