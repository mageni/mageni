###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_ios_xe_cisco-sa-20170419-ios-xe-snmp.nasl 12106 2018-10-26 06:33:36Z cfischer $
#
# Cisco IOS XE Software Simple Network Management Protocol Subsystem Denial of Service Vulnerability
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
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

CPE = "cpe:/o:cisco:ios_xe";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106779");
  script_cve_id("CVE-2017-6615");
  script_tag(name:"cvss_base", value:"6.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:N/A:C");
  script_version("$Revision: 12106 $");

  script_name("Cisco IOS XE Software Simple Network Management Protocol Subsystem Denial of Service Vulnerability");

  script_xref(name:"URL", value:"https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170419-ios-xe-snmp");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_tag(name:"summary", value:"A vulnerability in the Simple Network Management Protocol (SNMP) subsystem
of Cisco IOS XE Software could allow an authenticated, remote attacker to cause a denial of service (DoS)
condition.");

  script_tag(name:"insight", value:"The vulnerability is due to a race condition that could occur when the
affected software processes an SNMP read request that contains certain criteria for a specific object ID (OID)
and an active crypto session is disconnected on an affected device. An attacker who can authenticate to an
affected device could trigger this vulnerability by issuing an SNMP request for a specific OID on the device.");

  script_tag(name:"impact", value:"A successful exploit will cause the device to restart due to an attempt to
access an invalid memory region. The attacker does not control how or when crypto sessions are disconnected on
the device.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-04-20 16:12:29 +0200 (Thu, 20 Apr 2017)");
  script_category(ACT_GATHER_INFO);
  script_family("CISCO");
  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_dependencies("gb_cisco_ios_xe_version.nasl");
  script_mandatory_keys("cisco_ios_xe/version");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE))
  exit(0);

affected = make_list(
		'3.16.0S',
		'3.16.0cS',
		'3.16.1S',
		'3.16.1aS',
		'3.16.2S');

foreach af (affected) {
  if (version == af) {
    report = report_fixed_ver(installed_version: version, fixed_version: "See advisory");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);

