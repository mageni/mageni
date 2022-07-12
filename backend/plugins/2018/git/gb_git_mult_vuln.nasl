###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_git_mult_vuln.nasl 12116 2018-10-26 10:01:35Z mmartin $
#
# Git 2.13.x, 2.14.x, 2.15.x, 2.16.x, 2.17.x Multiple Vulnerabilities (Windows)
#
# Authors:
# Jan Philipp Schulte <jan.schulte@greenbone.net>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, https://www.greenbone.net
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
###############################################################################

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.113205");
  script_version("$Revision: 12116 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 12:01:35 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2018-05-31 14:37:56 +0200 (Thu, 31 May 2018)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"registry");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2018-11233", "CVE-2018-11235");

  script_name("Git 2.13.x, 2.14.x, 2.15.x, 2.16.x, 2.17.x Multiple Vulnerabilities (Windows)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_git_detect_win.nasl");
  script_mandatory_keys("Git/Win/Ver");

  script_tag(name:"summary", value:"Git is prone to multiple vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Following vulnerabilities exist:

  - Code to sanity-check pathnames on NTFS can result in reading out-of-bounds memory

  - With a crafted .gitmodules file, a malicious project can execute an arbitrary script on a machine that runs
    'git clone --recurse-submodules' because submodule 'names' are obtained from this file, and then appended
    to $GIT_DIR/modules, leading to directory traversal with '../' in a name.
    Finally, post-checkout hooks from a submodule are executed, bypassing the intended design in which hooks
    are not obtained from a remote server (Remote Code Execution can occur)");
  script_tag(name:"affected", value:"Git versions through 2.13.6, 2.14.0 through 2.14.3, 2.15.0 through 2.15.1, 2.16.0 through 2.16.3 and 2.17.0.");
  script_tag(name:"solution", value:"Update to version 2.13.7, 2.14.4, 2.15.2, 2.16.4 or 2.17.1 respectively.");

  script_xref(name:"URL", value:"https://marc.info/?l=git&m=152761328506724&w=2");
  script_xref(name:"URL", value:"https://securitytracker.com/id/1040991");
  script_xref(name:"URL", value:"https://blogs.msdn.microsoft.com/devops/2018/05/29/announcing-the-may-2018-git-security-vulnerability/");

  exit(0);
}

CPE = "cpe:/a:git_for_windows_project:git_for_windows";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! version = get_app_version( cpe: CPE, port: port ) ) exit( 0 );

if( version_is_less( version: version, test_version: "2.13.7" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "2.13.7" );
  security_message( data: report, port: port );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "2.14.0", test_version2: "2.14.3" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "2.14.4" );
  security_message( data: report, port: port );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "2.15.0", test_version2: "2.15.1" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "2.15.2" );
  security_message( data: report, port: port );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "2.16.0", test_version2: "2.16.3" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "2.16.4" );
  security_message( data: report, port: port );
  exit( 0 );
}

if( version_is_equal( version: version, test_version: "2.17.0" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "2.17.1" );
  security_message( data: report, port: port );
  exit( 0 );
}


exit( 99 );
