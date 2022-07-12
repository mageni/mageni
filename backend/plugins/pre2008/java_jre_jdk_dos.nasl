##############################################################################
# OpenVAS Vulnerability Test
#
# Sun Java Runtime Environment < 1.4.2_04 DoS
#
# Authors:
# William Craig
#
# Copyright:
# Copyright (C) 2004 Netteksecure Inc.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
##############################################################################

CPE = "cpe:/a:sun:jre";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.12244");
  script_version("2019-04-29T15:08:03+0000");
  script_tag(name:"last_modification", value:"2019-04-29 15:08:03 +0000 (Mon, 29 Apr 2019)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_cve_id("CVE-2004-0651");
  script_bugtraq_id(10301);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("Sun Java Runtime Environment < 1.4.2_04 DoS");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2004 Netteksecure Inc.");
  script_family("Windows");
  script_dependencies("gb_java_prdts_detect_portable_win.nasl");
  script_mandatory_keys("Sun/Java/JRE/Win/Ver");

  script_tag(name:"solution", value:"Upgrade to SDK and JRE 1.4.2_04.");

  script_tag(name:"summary", value:"The remote Windows machine is running a Java SDK or JRE version
  1.4.2_03 and prior which is vulnerable to a DoS attack.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE ) ) exit( 0 );
vers = infos['version'];
path = infos['location'];

if( vers && ereg( pattern:"^1\.4\.([01]|2_0[0-3])", string:vers ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"1.4.2_04", install_path:path );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );