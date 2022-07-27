###############################################################################
# OpenVAS Vulnerability Test
# $Id: wu_ftpd_skey_remote_buff.nasl 13602 2019-02-12 12:47:59Z cfischer $
#
# wu-ftpd S/KEY authentication overflow
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
# based on work from (C) Tenable Network Security
#
# Copyright:
# Copyright (C) 2004 David Maciejak
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

# Ref: Michal Zalewski & Michael Hendrickx

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.14372");
  script_version("$Revision: 13602 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-12 13:47:59 +0100 (Tue, 12 Feb 2019) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(8893);
  script_cve_id("CVE-2004-0185");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("wu-ftpd S/KEY authentication overflow");
  script_category(ACT_GATHER_INFO);
  script_family("FTP");
  script_copyright("This script is Copyright (C) 2004 David Maciejak");
  script_dependencies("gb_wu-ftpd_detect.nasl");
  script_require_ports("Services/ftp", 21);
  script_mandatory_keys("wu-ftpd/installed");

  script_xref(name:"URL", value:"http://www.wu-ftpd.org");

  script_tag(name:"summary", value:"The remote Wu-FTPd server seems to be vulnerable to a remote overflow.");

  script_tag(name:"insight", value:"This version contains a remote overflow if s/key support is enabled.

  The skey_challenge function fails to perform bounds checking on the
  name variable resulting in a buffer overflow.

  With a specially crafted request, an attacker can execute arbitrary
  code resulting in a loss of integrity and/or availability.

  It appears that this vulnerability may be exploited prior to authentication.
  It is reported that S/Key support is not enabled by default, though some
  operating system distributions which ship Wu-Ftpd may have it enabled.");

  script_tag(name:"solution", value:"Upgrade to Wu-FTPd 2.6.3 when available or disable SKEY or apply the
  patches available at the referenced vendor homepage.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( egrep( pattern:"^(2\.(5\.|6\.[012]))", string:vers ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"See references" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );