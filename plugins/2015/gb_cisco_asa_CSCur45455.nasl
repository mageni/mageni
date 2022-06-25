###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_asa_CSCur45455.nasl 12106 2018-10-26 06:33:36Z cfischer $
#
# Cisco ASA DHCPv6 Relay DoS Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.106053");
  script_version("$Revision: 12106 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-11-25 11:40:51 +0700 (Wed, 25 Nov 2015)");
  script_tag(name:"cvss_base", value:"5.7");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:M/Au:N/C:N/I:N/A:C");

  script_tag(name:"qod_type", value:"package");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2015-0578");
  script_bugtraq_id(72718);

  script_name("Cisco ASA DHCPv6 Relay DoS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("CISCO");
  script_dependencies("gb_cisco_asa_version.nasl");
  script_mandatory_keys("cisco_asa/version", "cisco_asa/model");

  script_tag(name:"summary", value:"A vulnerability in the DHCPv6 relay feature of Cisco ASA may
lead to a denial of service.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A vulnerability in the DHCPv6 relay feature could allow an
unauthenticated, remote attacker to cause an affected device to reload. The vulnerability is due to
insufficient validation of DHCPv6 packets. Cisco ASA Software is affected by this vulnerability only if
the software is configured with the DHCPv6 relay feature. An attacker could exploit this vulnerability by
sending crafted DHCPv6 packets to an affected device. Only DHCPv6 packets directed to the Cisco ASA interface
where the DHCPv6 relay feature is enabled can be used to trigger this vulnerability.");

  script_tag(name:"impact", value:"An unauthenticated, remote attacker could cause the system to reload.");

  script_tag(name:"affected", value:"Version 9.0, 9.1, 9.2 and 9.3 on Cisco Adaptive Security Virtual
Appliance (ASAv), Cisco ASA 1000V Cloud Firewall, Cisco ASA 5500 Series Adaptive Security Appliances,
Cisco ASA 5500-X Series Next-Generation Firewalls and Cisco ASA Services Module for Cisco Catalyst 6500
Series Switches and Cisco 7600 Series Routers");

  script_tag(name:"solution", value:"Apply the appropriate updates from Cisco. As a workaround disable
the DHCPv6 relay feature.");

  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/viewAlert.x?alertId=37022");
  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20150115-asa-dhcp");

  exit(0);
}

include("host_details.inc");
include("revisions-lib.inc");

model = get_kb_item("cisco_asa/model");
if (!model || (toupper(model) !~ "^ASAv" && toupper(model) !~ "^ASA55[0-9][0-9]"))
  exit(99);

if( ! version = get_app_version( cpe:CPE, nofork: TRUE ) ) exit( 0 );
compver = ereg_replace(string:version, pattern:"\(([0-9.]+)\)", replace:".\1");

if ((revcomp(a:compver, b:"9.0.4.37") < 0) &&
    (revcomp(a:compver, b:"9.0") >= 0)) {
  report = 'Installed Version: ' + version + '\n' +
           'Fixed Version:     9.0(4.37)\n';
  security_message(port: 0, data:report);
  exit(0);
}

if ((revcomp(a:compver, b:"9.1.5.21") < 0) &&
    (revcomp(a:compver, b:"9.1") >= 0)) {
  report = 'Installed Version: ' + version + '\n' +
           'Fixed Version:     9.1(5.21)\n';
  security_message(port: 0, data:report);
  exit(0);
}

if ((revcomp(a:compver, b:"9.2.4") < 0) &&
    (revcomp(a:compver, b:"9.2") >= 0)) {
  report = 'Installed Version: ' + version + '\n' +
           'Fixed Version:     9.2(4)\n';
  security_message(port: 0, data:report);
  exit(0);
}

if ((revcomp(a:compver, b:"9.3.2") < 0) &&
    (revcomp(a:compver, b:"9.3") >= 0)) {
  report = 'Installed Version: ' + version + '\n' +
           'Fixed Version:     9.3(2)\n';
  security_message(port: 0, data:report);
  exit(0);
}

exit(0);
