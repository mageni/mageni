###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_samba_51713.nasl 10398 2018-07-04 12:11:48Z cfischer $
#
# Samba Memory Leak Local Denial Of Service Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH
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
###############################################################################

CPE = "cpe:/a:samba:samba";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103411");
  script_version("$Revision: 10398 $");
  script_tag(name:"last_modification", value:"$Date: 2018-07-04 14:11:48 +0200 (Wed, 04 Jul 2018) $");
  script_tag(name:"creation_date", value:"2012-02-09 10:12:15 +0100 (Thu, 09 Feb 2012)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_bugtraq_id(51713);
  script_cve_id("CVE-2012-0817");
  script_name("Samba Memory Leak Local Denial Of Service Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
  script_dependencies("smb_nativelanman.nasl", "gb_samba_detect.nasl");
  script_mandatory_keys("samba/smb_or_ssh/detected");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/51713");
  script_xref(name:"URL", value:"http://www.samba.org/samba/security/CVE-2012-0817");
  script_xref(name:"URL", value:"http://www.samba.org");

  script_tag(name:"summary", value:"Samba is prone to a local denial-of-service vulnerability.");

  script_tag(name:"impact", value:"A local attacker can exploit this issue to exhaust available memory,
  denying access to legitimate users.");

  script_tag(name:"affected", value:"The vulnerability affects Samba versions 3.6.0 through 3.6.2.");

  script_tag(name:"solution", value:"Updates are available. Please see the references for details.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( isnull( port = get_app_port( cpe:CPE ) ) ) exit( 0 );
if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) ) exit( 0 );
vers = infos['version'];
loc = infos['location'];

if( version_in_range( version:vers, test_version:"3.6", test_version2:"3.6.2" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"3.6.3", install_path:loc );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
