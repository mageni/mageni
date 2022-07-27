###############################################################################
# OpenVAS Vulnerability Test
# $Id: wu_ftpd_site_exec.nasl 13602 2019-02-12 12:47:59Z cfischer $
#
# wu-ftpd SITE EXEC vulnerability
#
# Authors:
# Alexis de Bernis <alexisb@nessus.org>
# changes by rd :
# - rely on the banner if we could not log in
# - changed the description to include a Solution:
#
# Copyright:
# Copyright (C) 2000 A. de Bernis
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
###############################################################################

CPE = "cpe:/a:washington_university:wu-ftpd";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10452");
  script_version("$Revision: 13602 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-12 13:47:59 +0100 (Tue, 12 Feb 2019) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(1387, 2240, 726);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2000-0573", "CVE-1999-0997");
  script_name("wu-ftpd SITE EXEC vulnerability");
  script_category(ACT_GATHER_INFO);
  script_family("FTP");
  script_copyright("This script is Copyright (C) 2000 A. de Bernis");
  script_dependencies("gb_wu-ftpd_detect.nasl");
  script_require_ports("Services/ftp", 21);
  script_mandatory_keys("wu-ftpd/installed");

  script_tag(name:"summary", value:"The remote FTP server does not properly sanitize the argument of
  the SITE EXEC command.");

  script_tag(name:"impact", value:"It may be possible for a remote attacker to gain root access.");

  script_tag(name:"solution", value:"Upgrade your wu-ftpd server (<= 2.6.0 are vulnerable)
  or disable any access from untrusted users (especially anonymous).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( egrep( pattern:"^((1\..*)|(2\.[0-5]\..*)|(2\.6\.0))", string: vers ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"2.6.1" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
