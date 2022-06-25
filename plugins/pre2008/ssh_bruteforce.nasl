# OpenVAS Vulnerability Test
# Description: SSH1 SSH Daemon Logging Failure
#
# Authors:
# Xue Yong Zhi<xueyong@udel.edu>
#
# Copyright:
# Copyright (C) 2003 Xue Yong Zhi
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
#

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11341");
  script_version("2019-05-22T07:58:25+0000");
  script_bugtraq_id(2345);
  script_cve_id("CVE-2001-0471");
  script_tag(name:"last_modification", value:"2019-05-22 07:58:25 +0000 (Wed, 22 May 2019)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("SSH1 SSH Daemon Logging Failure");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2003 Xue Yong Zhi");
  script_family("Gain a shell remotely");
  script_dependencies("gb_openssh_consolidation.nasl", "gb_dropbear_ssh_detect.nasl");
  script_require_ports("Services/ssh", 22);
  script_mandatory_keys("ssh/server_banner/available");
  script_exclude_keys("openssh/detected", "dropbear/installed");

  script_tag(name:"solution", value:"Patch and new version are available from SSH.");

  script_tag(name:"summary", value:"You are running SSH Communications Security SSH 1.2.30, or previous.");

  script_tag(name:"insight", value:"This version does not log repeated login attempts, which~
  could allow remote attackers to compromise accounts without detection via a brute force attack.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("version_func.inc");
include("ssh_func.inc");

port = get_ssh_port( default:22 );
banner = get_ssh_server_banner( port:port );
if( ! banner )
  exit( 0 );

if( "openssh" >< tolower( banner ) || "dropbear" >< tolower( banner ) )
  exit( 99 );

#Looking for SSH product version number from 1.0 to 1.2.30
if( ereg( string:banner, pattern:"^SSH-.*-1\.([0-1]|[0-1]\..*|2\.([0-9]|1[0-9]|2[0-9]|30))[^0-9]*$", icase:TRUE ) ) {
  report = report_fixed_ver( installed_version:banner, fixed_version:"See references" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );