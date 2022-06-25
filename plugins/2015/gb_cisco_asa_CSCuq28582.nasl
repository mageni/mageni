###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_asa_CSCuq28582.nasl 12106 2018-10-26 06:33:36Z cfischer $
#
# Cisco ASA VPN Failover Command Injection Vulnerability
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2015 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
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

CPE = "cpe:/a:cisco:asa";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105982");
  script_version("$Revision: 12106 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-03-13 12:24:59 +0700 (Fri, 13 Mar 2015)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");

  script_tag(name:"qod_type", value:"package");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2014-3389");
  script_bugtraq_id(70297);

  script_name("Cisco ASA VPN Failover Command Injection Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("CISCO");
  script_dependencies("gb_cisco_asa_version.nasl", "gb_cisco_asa_version_snmp.nasl");
  script_mandatory_keys("cisco_asa/version");

  script_tag(name:"summary", value:"The VPN of Cisco ASA is prone to a command injection vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A vulnerability in the VPN code of Cisco ASA Software could allow an
authenticated, remote attacker to submit configuration commands to the standby unit via the failover interface.
As result, an attacker could be able to take full control of both the active and standby failover units.
The vulnerability is due to improper implementation of the internal filter for packets coming from an established
VPN tunnel. An attacker could exploit this vulnerability by sending crafted packets directed to the failover
interface IP address.");

  script_tag(name:"impact", value:"An authenticated, remote attacker could exploit this vulnerability by
connecting to a targeted device and sending malicious configuration requests through the failover interface to
the standby unit. The attacker could modify the configuration to take control over both the standby and active
units, resulting in complete device compromise.");

  script_tag(name:"affected", value:"Version 7.2, 8.2, 8.3, 8.4, 8.6, 9.0, 9.1, 9.2 and 9.3");

  script_tag(name:"solution", value:"Apply the appropriate updates from Cisco.");

  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/viewAlert.x?alertId=35912");

  exit(0);
}

include("host_details.inc");
include("revisions-lib.inc");

if( ! version = get_app_version( cpe:CPE, nofork: TRUE ) ) exit( 0 );
compver = ereg_replace(string:version, pattern:"\(([0-9.]+)\)", replace:".\1");

if ((revcomp(a:compver, b:"7.2.5.15") < 0) &&
    (revcomp(a:compver, b:"7.2") >= 0)) {
  report = 'Installed Version: ' + version + '\n' +
           'Fixed Version:     7.2(5.15)\n';
  security_message(port: 0, data:report);
  exit(0);
}

if ((revcomp(a:compver, b:"8.2.5.51") < 0) &&
    (revcomp(a:compver, b:"8.2") >= 0)) {
  report = 'Installed Version: ' + version + '\n' +
           'Fixed Version:     8.2(5.51)\n';
  security_message(port: 0, data:report);
  exit(0);
}

if ((revcomp(a:compver, b:"8.3.2.42") < 0) &&
    (revcomp(a:compver, b:"8.3") >= 0)) {
  report = 'Installed Version: ' + version + '\n' +
           'Fixed Version:     8.3(2.42)\n';
  security_message(port: 0, data:report);
  exit(0);
}

if ((revcomp(a:compver, b:"8.4.7.23") < 0) &&
    (revcomp(a:compver, b:"8.4") >= 0)) {
  report = 'Installed Version: ' + version + '\n' +
           'Fixed Version:     8.4(7.23)\n';
  security_message(port: 0, data:report);
  exit(0);
}

if ((revcomp(a:compver, b:"8.6.1.15") < 0) &&
    (revcomp(a:compver, b:"8.6") >= 0)) {
  report = 'Installed Version: ' + version + '\n' +
           'Fixed Version:     8.6(1.15)\n';
  security_message(port: 0, data:report);
  exit(0);
}

if ((revcomp(a:compver, b:"9.0.4.24") < 0) &&
    (revcomp(a:compver, b:"9.0") >= 0)) {
  report = 'Installed Version: ' + version + '\n' +
           'Fixed Version:     9.0(4.24)\n';
  security_message(port: 0, data:report);
  exit(0);
}

if ((revcomp(a:compver, b:"9.1.5.12") < 0) &&
    (revcomp(a:compver, b:"9.1") >= 0)) {
  report = 'Installed Version: ' + version + '\n' +
           'Fixed Version:     9.1(5.12)\n';
  security_message(port: 0, data:report);
  exit(0);
}

if ((revcomp(a:compver, b:"9.2.2.6") < 0) &&
    (revcomp(a:compver, b:"9.2") >= 0)) {
  report = 'Installed Version: ' + version + '\n' +
           'Fixed Version:     9.2(2.6)\n';
  security_message(port: 0, data:report);
  exit(0);
}

if ((revcomp(a:compver, b:"9.3.1.1") < 0) &&
    (revcomp(a:compver, b:"9.3") >= 0)) {
  report = 'Installed Version: ' + version + '\n' +
           'Fixed Version:     9.3(1.1)\n';
  security_message(port: 0, data:report);
  exit(0);
}

exit(0);
