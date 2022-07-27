###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_juniper_screenos_JSA10713.nasl 12106 2018-10-26 06:33:36Z cfischer $
#
# Multiple Security issues with ScreenOS (JSA10713)
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

CPE = "cpe:/o:juniper:screenos";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105494");
  script_cve_id("CVE-2015-7755", "CVE-2015-7754", "CVE-2015-7756");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_version("$Revision: 12106 $");

  script_name("Multiple Security issues with ScreenOS (JSA10713)");

  script_xref(name:"URL", value:"http://kb.juniper.net/index?page=content&id=JSA10713&actp=RSS");
  script_xref(name:"URL", value:"http://kb.juniper.net/index?page=content&id=JSA10712&actp=RSS");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The first issue allows unauthorized remote administrative access to the device over SSH or telnet. Exploitation of this vulnerability can lead to complete compromise
of the affected system. The second issue may allow a knowledgeable attacker who can monitor VPN traffic to decrypt that traffic. It is independent of the first issue.

The third issue may result in a system crash during a crafted SSH negotiation when ssh-pka is configured and enabled on the firewall. In the worst case scenario, the unhandled SSH exception resulting
in a system crash could lead to remote code execution. This issue can affect any product or platform running ScreenOS 6.3.0r20.

 In February 2018 it was discovered that this vulnerability is being exploited by the 'DoubleDoor' Internet of Things
 (IoT) Botnet.");

  script_tag(name:"solution", value:"This issue was fixed in ScreenOS 6.2.0r19, 6.3.0r21, and all subsequent releases.");

  script_tag(name:"summary", value:"ScreenOS is vulnerable to an unauthorized remote administrative access to the device over SSH or telnet and to unauthorized decrypting of VPN traffic");
  script_tag(name:"affected", value:"These issues can affect any product or platform running ScreenOS 6.2.0r15 through 6.2.0r18 and 6.3.0r12 through 6.3.0r20.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"last_modification", value:"$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-12-18 09:58:55 +0100 (Fri, 18 Dec 2015)");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("This script is Copyright (C) 2015 Greenbone Networks GmbH");
  script_dependencies("gb_screenos_version.nasl");
  script_mandatory_keys("ScreenOS/version");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! version = get_app_version( cpe:CPE ) ) exit( 0 );

display_version = version;

version = str_replace( string:version, find:"r", replace:"." );
version = str_replace( string:version, find:"-", replace:"." );

if( version =~ '^6\\.2\\.0' )
{
  if( version_is_less( version:version, test_version:"6.2.0.15" ) ) exit( 99 );

  display_fix = '6.2.0r19';
  fix = '6.2.0.19';
}
else if( version =~ '^6\\.3\\.0' )
{
  if( version_is_less( version:version, test_version:"6.3.0.12" ) ) exit( 99 );

  display_fix = '6.3.0r21';
  fix = '6.3.0.21';

  # Additionally, earlier affected releases of ScreenOS 6.3.0 have been respun to resolve these issues.
  # Fixes are included in: 6.3.0r12b, 6.3.0r13b, 6.3.0r14b, 6.3.0r15b, 6.3.0r16b, 6.3.0r17b, 6.3.0r18b, 6.3.0r19b.
  patched = make_list( "6.3.0r12b", "6.3.0r13b", "6.3.0r14b", "6.3.0r15b", "6.3.0r16b", "6.3.0r17b", "6.3.0r18b", "6.3.0r19b");
  foreach p ( patched )
    if( display_version =~ '^' + p ) exit( 99 );
}

if( ! fix ) exit( 99 );

if( version_is_less( version:version, test_version:fix ) )
{
  report = 'Installed version: ' + display_version + '\n' +
           'Fixed version:     ' + display_fix + '\n';

  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );

