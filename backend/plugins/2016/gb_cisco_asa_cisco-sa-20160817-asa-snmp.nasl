###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_asa_cisco-sa-20160817-asa-snmp.nasl 12149 2018-10-29 10:48:30Z asteins $
#
# Cisco Adaptive Security Appliance SNMP Remote Code Execution Vulnerability
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH
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

CPE = "cpe:/a:cisco:asa";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106183");
  script_cve_id("CVE-2016-6366");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_version("$Revision: 12149 $");

  script_name("Cisco Adaptive Security Appliance SNMP Remote Code Execution Vulnerability");

  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160817-asa-snmp");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");
  script_tag(name:"summary", value:"A vulnerability in the Simple Network Management Protocol (SNMP) code
of Cisco Adaptive Security Appliance (ASA) Software could allow an unauthenticated, remote attacker to cause
a reload of the affected system or to remotely execute code.

The vulnerability is due to a buffer overflow in the affected code area. An attacker could exploit this
vulnerability by sending crafted SNMP packets to the affected system. An exploit could allow the attacker to
execute arbitrary code and obtain full control of the system or to cause a reload of the affected system. The
attacker must know the SNMP community string to exploit this vulnerability.

Note: Only traffic directed to the affected system can be used to exploit this vulnerability. This vulnerability
affects systems configured in routed and transparent firewall mode only and in single or multiple context mode.
This vulnerability can be triggered by IPv4 traffic only. The attacker requires knowledge of the configured SNMP
community string in SNMP version 1 and SNMP version 2c or a valid username and password for SNMP version 3.

Cisco has released software updates that address this vulnerability.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"$Date: 2018-10-29 11:48:30 +0100 (Mon, 29 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-08-18 10:57:32 +0700 (Thu, 18 Aug 2016)");
  script_category(ACT_GATHER_INFO);
  script_family("CISCO");
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("gb_cisco_asa_version.nasl", "gb_cisco_asa_version_snmp.nasl");
  script_mandatory_keys("cisco_asa/version");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! version = get_app_version( cpe:CPE, nofork: TRUE ) ) exit( 0 );
check_vers = ereg_replace(string:version, pattern:"\(([0-9.]+)\)", replace:".\1");

if (version_is_less(version: check_vers, test_version: "9.0.4.40"))
{
  report = report_fixed_ver(  installed_version:version, fixed_version: "9.0.4(40)" );
  security_message( port:0, data:report );
  exit( 0 );
}

if (check_vers =~ "^9\.1") {
  if(version_is_less(version: check_vers, test_version: "9.1.7.9"))
  {
    report = report_fixed_ver(  installed_version:version, fixed_version: "9.1.7(9)" );
    security_message( port:0, data:report );
    exit( 0 );
  }
}

if (check_vers =~ "^9\.2") {
  if(version_is_less(version: check_vers, test_version: "9.2.4.14"))
  {
    report = report_fixed_ver(  installed_version:version, fixed_version: "9.2.4(14)" );
    security_message( port:0, data:report );
    exit( 0 );
  }
}

if (check_vers =~ "^9\.3") {
  if(version_is_less(version: check_vers, test_version: "9.3.3.10"))
  {
    report = report_fixed_ver(  installed_version:version, fixed_version: "9.3.3(10)" );
    security_message( port:0, data:report );
    exit( 0 );
  }
}

if (check_vers =~ "^9\.4") {
  if(version_is_less(version: check_vers, test_version: "9.4.3.8"))
  {
    report = report_fixed_ver(  installed_version:version, fixed_version: "9.4.3(8)" );
    security_message( port:0, data:report );
    exit( 0 );
  }
}

if (check_vers =~ "^9\.5") {
  if(version_is_less(version: check_vers, test_version: "9.5.3"))
  {
    report = report_fixed_ver(  installed_version:version, fixed_version: "9.5(3)" );
    security_message( port:0, data:report );
    exit( 0 );
  }
}

if (check_vers =~ "^9\.6") {
  if(version_is_less(version: check_vers, test_version: "9.6.2"))
  {
    report = report_fixed_ver(  installed_version:version, fixed_version: "9.6.2" );
    security_message( port:0, data:report );
    exit( 0 );
  }
}

exit( 99 );

