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
  script_oid("1.3.6.1.4.1.25623.1.0.117713");
  script_version("2021-10-13T08:01:25+0000");
  script_cve_id("CVE-2020-11443");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:C/A:C");
  script_tag(name:"last_modification", value:"2021-10-13 11:12:06 +0000 (Wed, 13 Oct 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-05-14 01:15:00 +0000 (Thu, 14 May 2020)");
  script_tag(name:"creation_date", value:"2021-10-12 12:18:21 +0000 (Tue, 12 Oct 2021)");
  script_name("Zoom Client < 4.6.10 Windows Installer Vulnerability (ZSB-20001) - Windows");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_zoom_client_smb_login_detect.nasl");
  script_mandatory_keys("zoom/client/win/detected");

  script_xref(name:"URL", value:"https://explore.zoom.us/en/trust/security/security-bulletin/");

  script_tag(name:"summary", value:"Zoom Client is prone to a vulnerability in the Windows
  installer.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A vulnerability in how the Zoom Windows installer handles
  junctions when deleting files could allow a local Windows user to delete files otherwise not
  deletable by the user.

  The vulnerability is due to insufficient checking for junctions in the directory from which the
  installer deletes files, which is writable by standard users. A malicious local user could exploit
  this vulnerability by creating a junction in the affected directory that points to protected
  system files or other files to which the user does not have permissions. Upon running the Zoom
  Windows installer with elevated permissions, as is the case when it is run through managed
  deployment software, those files would get deleted from the system.");

  script_tag(name:"affected", value:"Zoom Client versions prior to 4.6.10 on Windows.");

  script_tag(name:"solution", value:"Update to version 4.6.10 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE ) )
  exit( 0 );

vers = infos["version"];
path = infos["location"];

if( version_is_less( version:vers, test_version:"4.6.10" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"4.6.10", install_path:path );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );