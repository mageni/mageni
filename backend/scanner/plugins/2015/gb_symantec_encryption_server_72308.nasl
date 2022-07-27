###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_symantec_encryption_server_72308.nasl 12106 2018-10-26 06:33:36Z cfischer $
#
# Symantec Encryption Management Server Local Command Injection Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2015 Greenbone Networks GmbH
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

CPE = "cpe:/a:symantec:encryption_management_server";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105301");
  script_bugtraq_id(72308);
  script_cve_id("CVE-2014-7288");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_version("$Revision: 12106 $");

  script_name("Symantec Encryption Management Server  Local Command Injection Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/72308");
  script_xref(name:"URL", value:"http://www.symantec.com/security_response/securityupdates/detail.jsp?fid=security_advisory&pvid=security_advisory&year=&suid=20150129_00M");

  script_tag(name:"impact", value:"A local attacker can exploit this issue to execute arbitrary commands with elevated privileges.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Symantec Encryption Management Server is susceptible to a shell command line injection when an authorized, but less privileged administrator,
is submitting a request for a database backup.  This could potentially result in the malicious administrator gaining privileged access on the server.

Symantec Encryption Management Server is susceptible to an email header injection utilizing a specifically formatted PGP key submitted to the integrated key management server.
The injection could potentially allow a malicious individual to manipulate specific areas of the confirmation email, for example, modifying the contents of some of the email
fields such as the subject field.");

  script_tag(name:"solution", value:"Update to 3.3.2 MP7 or later.");

  script_tag(name:"summary", value:"Symantec Encryption Management Server is prone to a local command-injection vulnerability.");
  script_tag(name:"affected", value:"Symantec Encryption Management Server / Symantec PGP Universal Server 3.3.2 MP6 and prior");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"package");

  script_tag(name:"last_modification", value:"$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-06-18 15:29:34 +0200 (Thu, 18 Jun 2015)");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("This script is Copyright (C) 2015 Greenbone Networks GmbH");
  script_dependencies("gb_symantec_encryption_server_version.nasl");
  script_mandatory_keys("symantec_encryption_server/version");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! version = get_app_version( cpe:CPE ) ) exit( 0 );

if( version_is_less( version:version, test_version:"3.3.2" ) ) VULN = TRUE;

mp = get_kb_item( "symantec_encryption_server/MP_VALUE" );
build = get_kb_item( "symantec_encryption_server/build" );

if( version == '3.3.2' )
{
  if( mp && int( mp ) < 7 ) VULN = TRUE;
  if( build && int( build ) < 16127 ) VULN = TRUE;

}

if( VULN )
{
  report = 'Installed version: ' + version + '\n';
  if( mp ) report += 'MP:                '  + mp + '\n';
  if( build ) report += 'Installed build:   '  + build + '\n';

  report += '\nFixed version:     3.3.2 MP7\n' +
            'Fixed build:       16127';

  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );

