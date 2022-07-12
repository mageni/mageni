###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_apic_cisco-sa-20160921-apic.nasl 14041 2019-03-08 01:52:05Z ckuersteiner $
#
# Cisco Application Policy Infrastructure Controller Binary Privilege Escalation Vulnerability
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

CPE = "cpe:/a:cisco:application_policy_infrastructure_controller";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106283");
  script_cve_id("CVE-2016-6413");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_version("$Revision: 14041 $");

  script_name("Cisco Application Policy Infrastructure Controller Binary Privilege Escalation Vulnerability");

  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160921-apic");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_tag(name:"summary", value:"A vulnerability in the installation procedure for Cisco Application Policy
Infrastructure Controller (APIC) devices could allow an authenticated, local attacker to gain root-level
privileges.");

  script_tag(name:"insight", value:"The vulnerability is due to incorrect installation and permissions settings
for binary files when installing the system software on a device. An attacker could exploit this vulnerability
by logging in to the device and escalating their privileges.");

  script_tag(name:"impact", value:"A successful exploit could allow the attacker to gain root-level privileges
and take full control of the device.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"$Date: 2019-03-08 02:52:05 +0100 (Fri, 08 Mar 2019) $");
  script_tag(name:"creation_date", value:"2016-09-22 10:06:54 +0700 (Thu, 22 Sep 2016)");
  script_category(ACT_GATHER_INFO);
  script_family("CISCO");
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("gb_cisco_apic_web_detect.nasl");
  script_mandatory_keys("cisco/application_policy_infrastructure_controller/installed");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! version = get_app_version( cpe:CPE ) ) exit( 0 );

if( version == '1.3(2f)' ) {
  report = report_fixed_ver(  installed_version:version, fixed_version: "See advisory" );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );

