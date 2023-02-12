# Copyright (C) 2023 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.170303");
  script_version("2023-02-06T10:09:59+0000");
  script_tag(name:"last_modification", value:"2023-02-06 10:09:59 +0000 (Mon, 06 Feb 2023)");
  script_tag(name:"creation_date", value:"2023-02-03 09:20:43 +0000 (Fri, 03 Feb 2023)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:P/A:N");

  script_cve_id("CVE-2022-48140");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"NoneAvailable");

  script_name("DedeCMS 5.x XSS Vulnerability (Dec 2022)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_dedecms_http_detect.nasl");
  script_mandatory_keys("dedecms/detected");

  script_tag(name:"summary", value:"DedeCMS is prone to a cross-site scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"DedeCMS was discovered to contain an XSS vulnerability in the
  component /file_manage_view.php?fmdo=edit&filename.");

  script_tag(name:"affected", value:"All versions of DedeCMS V5.7 SP2.");

  script_tag(name:"solution", value:"No known solution is available as of 03rd February, 2023.
  Information regarding this issue will be updated once solution details are available.");

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

if ( version =~ "^5" ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"None", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
