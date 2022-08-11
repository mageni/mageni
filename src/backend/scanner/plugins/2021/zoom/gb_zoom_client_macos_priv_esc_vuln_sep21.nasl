# Copyright (C) 2021 Greenbone Networks GmbH
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

CPE = "cpe:/a:zoom:zoom";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.118238");
  script_version("2021-09-29T13:12:01+0000");
  script_cve_id("CVE-2021-34409");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2021-09-30 10:16:12 +0000 (Thu, 30 Sep 2021)");
  script_tag(name:"creation_date", value:"2021-09-29 13:47:33 +0200 (Wed, 29 Sep 2021)");
  script_name("Zoom Client for Meetings for MacOS < 5.2.0 Privilege Escalation Vulnerability");

  script_tag(name:"summary", value:"Zoom Client for Meetings for MacOS is prone to a privilege
  escalation vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"User-writable pre and post-install scripts unpacked during the
  installation allow for privilege escalation to root.");

  script_tag(name:"affected", value:"All versions of the Zoom Client for Meetings for MacOS before
  5.2.0.");

  script_tag(name:"solution", value:"Update to version 5.2.0 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Privilege escalation");
  script_dependencies("gb_zoom_client_detect_macosx.nasl");
  script_mandatory_keys("zoom/client/mac/detected");

  script_xref(name:"URL", value:"https://explore.zoom.us/en/trust/security/security-bulletin");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE ) )
  exit( 0 );

vers = infos["version"];
path = infos["location"];

if( version_is_less( version:vers, test_version:"5.2.0" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"5.2.0", install_path:path );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
