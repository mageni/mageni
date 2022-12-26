# Copyright (C) 2022 Greenbone Networks GmbH
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

CPE = "cpe:/a:dedecms:dedecms";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.170258");
  script_version("2022-12-06T10:11:16+0000");
  script_tag(name:"last_modification", value:"2022-12-06 10:11:16 +0000 (Tue, 06 Dec 2022)");
  script_tag(name:"creation_date", value:"2022-12-01 15:11:58 +0000 (Thu, 01 Dec 2022)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2022-43031");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"NoneAvailable");

  script_name("DedeCMS V6 <= 6.1.9 CSRF Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_dedecms_http_detect.nasl");
  script_mandatory_keys("dedecms/detected");

  script_tag(name:"summary", value:"DedeCMS is prone to a cross-site request forgery (CSRF)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"The vulnerability allows attackers to arbitrarily add
  administrator accounts and modify admin passwords.");

  script_tag(name:"affected", value:"DedeCMS V6 SP2 through version 6.1.9.");

  script_tag(name:"solution", value:"No known solution is available as of 01st December, 2022.
  Information regarding this issue will be updated once solution details are available.");

  script_xref(name:"URL", value:"https://github.com/cai-niao98/Dedecmsv6");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if ( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if ( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];
# nb: There are two distinct lines of the product; making sure we handle the right one
if (version =~ "^6") {
  if ( version_is_less_equal( version:version, test_version:"6.1.9" ) ) {
    report = report_fixed_ver( installed_version:version, fixed_version:"None", install_path:location );
    security_message( port:port, data:report );
    exit( 0 );
  }
} else {
  # nb: This vulnerability probably does not affect the 5.x versions as V6 is a rewrite of the platform
  exit( 99 );
}

exit( 0 );
