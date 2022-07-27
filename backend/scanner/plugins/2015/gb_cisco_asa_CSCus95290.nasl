###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_asa_CSCus95290.nasl 12106 2018-10-26 06:33:36Z cfischer $
#
# Cisco ASA VPN XML Parser DoS Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.106000");
  script_version("$Revision: 12106 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-05-29 15:12:10 +0700 (Fri, 29 May 2015)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_tag(name:"qod_type", value:"package");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2015-0677");
  script_bugtraq_id(73967);

  script_name("Cisco ASA VPN XML Parser DoS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("CISCO");
  script_dependencies("gb_cisco_asa_version.nasl", "gb_cisco_asa_version_snmp.nasl");
  script_mandatory_keys("cisco_asa/version");

  script_tag(name:"summary", value:"Cisco ASA is prone to a DoS vulnerability in the VPN XML Parser.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The vulnerability is due to insufficient hardening of the XML
parser configuration. An attacker could exploit this vulnerability by sending a crafted XML message to
the affected system. This vulnerability affects Cisco ASA appliances configured for Clientless or AnyConnect
SSL VPN and AnyConnect IKEv2 VPN. All other VPN configurations are unaffected by this vulnerability.");

  script_tag(name:"impact", value:"An unauthenticated, remote attacker could exploit this vulnerability
by sending a crafted XML message to a targeted system. A successful exploit could cause the WebVPN component
on the system to crash, resulting in a DoS condition.");

  script_tag(name:"affected", value:"Version 8.4, 8.6, 9.0, 9.1, 9.2 and 9.3");

  script_tag(name:"solution", value:"Apply the appropriate updates from Cisco.");

  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/viewAlert.x?alertId=38185");

  exit(0);
}

include("host_details.inc");
include("revisions-lib.inc");

if( ! version = get_app_version( cpe:CPE, nofork: TRUE ) ) exit( 0 );
compver = ereg_replace(string:version, pattern:"\(([0-9.]+)\)", replace:".\1");

if ((revcomp(a:compver, b:"8.4.7.28") < 0) &&
    (revcomp(a:compver, b:"8.4") >= 0)) {
  report = 'Installed Version: ' + version + '\n' +
           'Fixed Version:     8.4(7.28)\n';
  security_message(port: 0, data:report);
  exit(0);
}

if ((revcomp(a:compver, b:"8.6.1.17") < 0) &&
    (revcomp(a:compver, b:"8.6") >= 0)) {
  report = 'Installed Version: ' + version + '\n' +
           'Fixed Version:     8.4(3)\n';
  security_message(port: 0, data:report);
  exit(0);
}

if ((revcomp(a:compver, b:"9.0.4.33") < 0) &&
    (revcomp(a:compver, b:"9.0") >= 0)) {
  report = 'Installed Version: ' + version + '\n' +
           'Fixed Version:     9.0(4.33)\n';
  security_message(port: 0, data:report);
  exit(0);
}

if ((revcomp(a:compver, b:"9.1.6") < 0) &&
    (revcomp(a:compver, b:"9.1") >= 0)) {
  report = 'Installed Version: ' + version + '\n' +
           'Fixed Version:     9.1(6)\n';
  security_message(port: 0, data:report);
  exit(0);
}

if ((revcomp(a:compver, b:"9.2.3.4") < 0) &&
    (revcomp(a:compver, b:"9.2") >= 0)) {
  report = 'Installed Version: ' + version + '\n' +
           'Fixed Version:     9.2(3.4)\n';
  security_message(port: 0, data:report);
  exit(0);
}

if ((revcomp(a:compver, b:"9.3.3") < 0) &&
    (revcomp(a:compver, b:"9.3") >= 0)) {
  report = 'Installed Version: ' + version + '\n' +
           'Fixed Version:     9.3(3)\n';
  security_message(port: 0, data:report);
  exit(0);
}

exit(0);
