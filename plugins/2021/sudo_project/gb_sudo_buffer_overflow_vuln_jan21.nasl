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

CPE = "cpe:/a:sudo_project:sudo";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.117186");
  script_version("2021-01-27T09:43:05+0000");
  script_cve_id("CVE-2021-3156");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2021-01-27 12:03:44 +0000 (Wed, 27 Jan 2021)");
  script_tag(name:"creation_date", value:"2021-01-27 06:47:49 +0000 (Wed, 27 Jan 2021)");
  script_name("Sudo Heap-Based Buffer Overflow (Baron Samedit) Vulnerability (Version-based LSC)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("gb_sudo_ssh_login_detect.nasl");
  script_mandatory_keys("sudo/ssh-login/detected");
  script_exclude_keys("ssh/force/pty");

  script_xref(name:"URL", value:"https://www.sudo.ws/stable.html#1.9.5p2");
  script_xref(name:"URL", value:"https://blog.qualys.com/vulnerabilities-research/2021/01/26/cve-2021-3156-heap-based-buffer-overflow-in-sudo-baron-samedit");

  script_tag(name:"summary", value:"Sudo is prone to a heap-based buffer overflow dubbed 'Baron Samedit'.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Sudo is allowing privilege escalation to root via 'sudoedit -s' and a
  command-line argument that ends with a single backslash character.");

  script_tag(name:"affected", value:"All legacy versions from 1.8.2 to 1.8.31p2 and all stable versions
  from 1.9.0 to 1.9.5p1 in their default configuration.");

  script_tag(name:"solution", value:"Update to version 1.9.5p2 or later.");

  script_tag(name:"qod_type", value:"executable_version_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("revisions-lib.inc");
include("version_func.inc");

if( ! infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE ) )
  exit( 0 );

vers = infos["version"];
path = infos["location"];

if( version_is_less( version:vers, test_version:"1.8.2" ) )
  exit( 99 ); # nb: Not affected

if( version_is_less( version:vers, test_version:"1.9.5p2" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"1.9.5p2", install_path:path );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
