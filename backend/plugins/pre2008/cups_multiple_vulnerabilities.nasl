###############################################################################
# OpenVAS Vulnerability Test
# $Id: cups_multiple_vulnerabilities.nasl 13975 2019-03-04 09:32:08Z cfischer $
#
# CUPS < 1.1.23 Multiple Vulnerabilities
#
# Authors:
# George A. Theall, <theall@tifaware.com>
#
# Copyright:
# Copyright (C) 2005 George A. Theall
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:apple:cups";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.16141");
  script_version("$Revision: 13975 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-04 10:32:08 +0100 (Mon, 04 Mar 2019) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_cve_id("CVE-2004-1267", "CVE-2004-1268", "CVE-2004-1269", "CVE-2004-1270", "CVE-2005-2874");
  script_bugtraq_id(11968, 12004, 12005, 12007, 12200, 14265);
  script_name("CUPS < 1.1.23 Multiple Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2005 George A. Theall");
  script_family("Gain a shell remotely");
  script_dependencies("secpod_cups_detect.nasl");
  script_require_ports("Services/www", 631);
  script_mandatory_keys("CUPS/installed");

  script_xref(name:"URL", value:"http://www.cups.org/str.php?L700");
  script_xref(name:"URL", value:"http://www.cups.org/str.php?L1024");
  script_xref(name:"URL", value:"http://www.cups.org/str.php?L1023");
  script_xref(name:"URL", value:"http://www.cups.org/str.php?L1042");

  script_tag(name:"solution", value:"Upgrade to CUPS 1.1.23 or later.");
  script_tag(name:"summary", value:"The remote host is running a CUPS server whose version number is
  between 1.0.4 and 1.1.22 inclusive. Such versions are prone to
  multiple vulnerabilities :

  - The is_path_absolute function in scheduler/client.c for the
    daemon in CUPS allows remote attackers to cause a denial
    of service (CPU consumption by tight loop) via a '..\..'
    URL in an HTTP request.

  - A remotely exploitable buffer overflow in the 'hpgltops'
    filter that enable specially crafted HPGL files can
    execute arbitrary commands as the CUPS 'lp' account.

  - A local user may be able to prevent anyone from changing
    his or her password until a temporary copy of the new
    password file is cleaned up ('lppasswd' flaw).

  - A local user may be able to add arbitrary content to the
    password file by closing the stderr file descriptor
    while running lppasswd (lppasswd flaw).

  - A local attacker may be able to truncate the CUPS
    password file, thereby denying service to valid clients
    using digest authentication. (lppasswd flaw).

  - The application applies ACLs to incoming print jobs in a
    case-sensitive fashion. Thus, an attacker can bypass
    restrictions by changing the case in printer names when
    submitting jobs. [Fixed in 1.1.21.]");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( version_is_less( version:vers, test_version:"1.1.23" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"1.1.23" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
