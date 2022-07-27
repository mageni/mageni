###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_phpbb_rce_nov18.nasl 12889 2018-12-28 07:52:20Z mmartin $
#
# phpBB < 3.2.4 Remote Code Execution Vulnerability
#
# Authors:
# Christian Fischer <christian.fischer@greenbone.net>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH
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

CPE = "cpe:/a:phpbb:phpbb";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108482");
  script_version("$Revision: 12889 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-28 08:52:20 +0100 (Fri, 28 Dec 2018) $");
  script_tag(name:"creation_date", value:"2018-11-21 09:03:29 +0100 (Wed, 21 Nov 2018)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_cve_id("CVE-2018-19274");
  script_name("phpBB < 3.2.4 Remote Code Execution Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("phpbb_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("phpBB/installed");

  script_tag(name:"summary", value:"phpBB is prone to Remote Code Execution through Object Injection.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Passing an absolute path to a file_exists check allows Remote Code Execution through Object
  Injection by employing Phar deserialization when an attacker has access to the Admin Control Panel with founder permissions.");

  script_tag(name:"impact", value:"Successful exploitation allows remote code execution for users with founder permissions to
  gain access to the underlying system.");

  script_tag(name:"affected", value:"phpBB versions before 3.2.4.");

  script_tag(name:"solution", value:"Update to version 3.2.4 or later.");

  script_xref(name:"URL", value:"https://wiki.phpbb.com/Release_Highlights/3.2.4");
  script_xref(name:"URL", value:"https://www.phpbb.com/community/viewtopic.php?f=14&t=2492206");

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

if( version_is_less( version:vers, test_version:"3.2.4" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"3.2.4", install_path:path );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );