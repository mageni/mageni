##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_wireshark_mult_vuln_sept08_lin_900213.nasl 12727 2018-12-10 07:22:33Z cfischer $
# Description: Wireshark Multiple Vulnerabilities - Sept-08 (Linux)
#
# Authors:
# Chandan S <schandan@secpod.com>
#
# Copyright:
# Copyright (C) 2008 SecPod, http://www.secpod.com
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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

CPE = "cpe:/a:wireshark:wireshark";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900213");
  script_version("$Revision: 12727 $");
  script_bugtraq_id(31009);
  script_cve_id("CVE-2008-3146", "CVE-2008-3932", "CVE-2008-3933");
  script_copyright("Copyright (C) 2008 SecPod");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-12-10 08:22:33 +0100 (Mon, 10 Dec 2018) $");
  script_tag(name:"creation_date", value:"2008-09-10 17:51:23 +0200 (Wed, 10 Sep 2008)");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_name("Wireshark Multiple Vulnerabilities - Sept08 (Linux)");
  script_dependencies("gb_wireshark_detect_lin.nasl");
  script_mandatory_keys("Wireshark/Linux/Ver");

  script_xref(name:"URL", value:"http://secunia.com/advisories/31674");
  script_xref(name:"URL", value:"http://www.frsirt.com/english/advisories/2008/2493");
  script_xref(name:"URL", value:"http://www.wireshark.org/security/wnpa-sec-2008-05.html");

  script_tag(name:"summary", value:"Check for vulnerable version of Wireshark.");

  script_tag(name:"affected", value:"Wireshark versions 1.0.2 and prior on Linux (All).");

  script_tag(name:"solution", value:"Upgrade to wireshark 1.0.3 or later.");

  script_tag(name:"impact", value:"Successful exploitation could result in denial of service
  condition or application crash by injecting a series of malformed
  packets or by convincing the victim to read a malformed packet.");

  script_tag(name:"qod_type", value:"executable_version_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE ) )
  exit( 0 );

vers = infos['version'];
path = infos['location'];

if( egrep( pattern:"wireshark 0\.99\.[1-5]$", string:vers ) ||
    egrep( pattern:"(0\.99\.[6-9]|1\.0\.[0-2])$", string:vers ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"1.0.3", install_path:path );
  security_message( port:0, data:report );
}

exit( 0 );