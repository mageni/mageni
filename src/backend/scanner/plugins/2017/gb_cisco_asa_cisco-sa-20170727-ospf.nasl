###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_asa_cisco-sa-20170727-ospf.nasl 12106 2018-10-26 06:33:36Z cfischer $
#
# Cisco ASA OSPF LSA Manipulation Vulnerability
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
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
  script_oid("1.3.6.1.4.1.25623.1.0.106994");
  script_cve_id("CVE-2017-6770");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:M/Au:N/C:N/I:P/A:P");
  script_version("$Revision: 12106 $");

  script_name("Cisco ASA OSPF LSA Manipulation Vulnerability");

  script_xref(name:"URL", value:"https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170727-ospf");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_tag(name:"summary", value:"Cisco ASA is affected by a vulnerability involving the Open Shortest Path
First (OSPF) Routing Protocol Link State Advertisement (LSA) database. This vulnerability could allow an
unauthenticated, remote attacker to take full control of the OSPF Autonomous System (AS) domain routing table,
allowing the attacker to intercept or black-hole traffic.");

  script_tag(name:"insight", value:"The attacker could exploit this vulnerability by injecting crafted OSPF
packets. To exploit this vulnerability, an attacker must accurately determine certain parameters within the LSA
database on the target router. This vulnerability can only be triggered by sending crafted unicast or multicast
OSPF LSA type 1 packets. No other LSA type packets can trigger this vulnerability.

OSPFv3 is not affected by this vulnerability. Fabric Shortest Path First (FSPF) protocol is not affected by this
vulnerability.");

  script_tag(name:"impact", value:"Successful exploitation could cause the targeted router to flush its routing
table and propagate the crafted OSPF LSA type 1 update throughout the OSPF AS domain.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-07-28 09:32:54 +0700 (Fri, 28 Jul 2017)");
  script_category(ACT_GATHER_INFO);
  script_family("CISCO");
  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_dependencies("gb_cisco_asa_version.nasl", "gb_cisco_asa_version_snmp.nasl");
  script_mandatory_keys("cisco_asa/version");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

check_vers = ereg_replace(string: version, pattern: "\(([0-9.]+)\)", replace: ".\1");

affected = make_list(
		'100.14.0.4',
		'100.14.1.1',
		'7.0.1',
		'7.0.1.4',
		'7.0.2',
		'7.0.3',
		'7.0.4',
		'7.0.4.2',
		'7.0.5',
		'7.0.5.12',
		'7.0.6',
		'7.0.6.18',
		'7.0.6.22',
		'7.0.6.26',
		'7.0.6.29',
		'7.0.6.32',
		'7.0.6.4',
		'7.0.6.8',
		'7.0.7',
		'7.0.7.1',
		'7.0.7.12',
		'7.0.7.4',
		'7.0.7.9',
		'7.0.8',
		'7.0.8.12',
		'7.0.8.13',
		'7.0.8.2',
		'7.0.8.8',
		'7.1.2',
		'7.1.2.16',
		'7.1.2.20',
		'7.1.2.24',
		'7.1.2.28',
		'7.1.2.38',
		'7.1.2.42',
		'7.1.2.46',
		'7.1.2.49',
		'7.1.2.53',
		'7.1.2.61',
		'7.1.2.64',
		'7.1.2.72',
		'7.1.2.81',
		'7.2.1',
		'7.2.1.13',
		'7.2.1.19',
		'7.2.1.24',
		'7.2.1.9',
		'7.2.2',
		'7.2.2.10',
		'7.2.2.14',
		'7.2.2.18',
		'7.2.2.19',
		'7.2.2.22',
		'7.2.2.34',
		'7.2.2.6',
		'7.2.3',
		'7.2.3.1',
		'7.2.3.12',
		'7.2.3.16',
		'7.2.4',
		'7.2.4.18',
		'7.2.4.25',
		'7.2.4.27',
		'7.2.4.30',
		'7.2.4.33',
		'7.2.4.6',
		'7.2.4.9',
		'7.2.5',
		'7.2.5.10',
		'7.2.5.12',
		'7.2.5.16',
		'7.2.5.2',
		'7.2.5.4',
		'7.2.5.7',
		'7.2.5.8',
		'8.0.1.2',
		'8.0.2',
		'8.0.2.11',
		'8.0.2.15',
		'8.0.3',
		'8.0.3.12',
		'8.0.3.19',
		'8.0.3.6',
		'8.0.4',
		'8.0.4.16',
		'8.0.4.23',
		'8.0.4.25',
		'8.0.4.28',
		'8.0.4.3',
		'8.0.4.31',
		'8.0.4.32',
		'8.0.4.33',
		'8.0.4.9',
		'8.0.5',
		'8.0.5.20',
		'8.0.5.23',
		'8.0.5.25',
		'8.0.5.27',
		'8.0.5.28',
		'8.0.5.31',
		'8.1.0.104',
		'8.1.1',
		'8.1.1.6',
		'8.1.2',
		'8.1.2.13',
		'8.1.2.15',
		'8.1.2.16',
		'8.1.2.19',
		'8.1.2.23',
		'8.1.2.24',
		'8.1.2.49',
		'8.1.2.50',
		'8.1.2.55',
		'8.1.2.56',
		'8.2.0.45',
		'8.2.1',
		'8.2.1.11',
		'8.2.2',
		'8.2.2.10',
		'8.2.2.12',
		'8.2.2.16',
		'8.2.2.17',
		'8.2.2.9',
		'8.2.3',
		'8.2.4',
		'8.2.4.1',
		'8.2.4.4',
		'8.2.5',
		'8.2.5.13',
		'8.2.5.22',
		'8.2.5.26',
		'8.2.5.33',
		'8.2.5.40',
		'8.2.5.41',
		'8.2.5.46',
		'8.2.5.48',
		'8.2.5.50',
		'8.2.5.52',
		'8.2.5.55',
		'8.2.5.57',
		'8.2.5.59',
		'8.3.1',
		'8.3.1.1',
		'8.3.1.4',
		'8.3.1.6',
		'8.3.2',
		'8.3.2.13',
		'8.3.2.23',
		'8.3.2.25',
		'8.3.2.31',
		'8.3.2.33',
		'8.3.2.34',
		'8.3.2.37',
		'8.3.2.39',
		'8.3.2.4',
		'8.3.2.40',
		'8.3.2.41',
		'8.3.2.44',
		'8.4.0',
		'8.4.1',
		'8.4.1.11',
		'8.4.1.3',
		'8.4.2',
		'8.4.2.1',
		'8.4.2.8',
		'8.4.3',
		'8.4.3.8',
		'8.4.3.9',
		'8.4.4',
		'8.4.4.1',
		'8.4.4.3',
		'8.4.4.5',
		'8.4.4.9',
		'8.4.5',
		'8.4.5.6',
		'8.4.6',
		'8.4.7',
		'8.4.7.15',
		'8.4.7.22',
		'8.4.7.23',
		'8.4.7.26',
		'8.4.7.28',
		'8.4.7.29',
		'8.4.7.3',
		'8.5.1',
		'8.5.1.1',
		'8.5.1.14',
		'8.5.1.17',
		'8.5.1.18',
		'8.5.1.19',
		'8.5.1.21',
		'8.5.1.24',
		'8.5.1.6',
		'8.5.1.7',
		'8.6.1',
		'8.6.1.1',
		'8.6.1.10',
		'8.6.1.12',
		'8.6.1.13',
		'8.6.1.14',
		'8.6.1.17',
		'8.6.1.2',
		'8.6.1.5',
		'8.7.1',
		'8.7.1.1',
		'8.7.1.11',
		'8.7.1.13',
		'8.7.1.16',
		'8.7.1.17',
		'8.7.1.3',
		'8.7.1.4',
		'8.7.1.7',
		'8.7.1.8',
		'9.0.1',
		'9.0.2',
		'9.0.2.10',
		'9.0.3',
		'9.0.3.6',
		'9.0.3.8',
		'9.0.4',
		'9.0.4.1',
		'9.0.4.17',
		'9.0.4.20',
		'9.0.4.24',
		'9.0.4.26',
		'9.0.4.29',
		'9.0.4.33',
		'9.0.4.35',
		'9.0.4.37',
		'9.0.4.40',
		'9.0.4.42',
		'9.0.4.5',
		'9.0.4.7',
		'9.1.1',
		'9.1.1.4',
		'9.1.2',
		'9.1.2.8',
		'9.1.3',
		'9.1.3.2',
		'9.1.4',
		'9.1.4.5',
		'9.1.5',
		'9.1.5.10',
		'9.1.5.12',
		'9.1.5.15',
		'9.1.5.21',
		'9.1.6',
		'9.1.6.1',
		'9.1.6.10',
		'9.1.6.4',
		'9.1.6.6',
		'9.1.6.8',
		'9.1.7.11',
		'9.1.7.12',
		'9.1.7.13',
		'9.1.7.15',
		'9.1.7.4',
		'9.1.7.6',
		'9.1.7.7',
		'9.1.7.9',
		'9.2.0.0',
		'9.2.0.104',
		'9.2.3.1',
		'9.2.1',
		'9.2.2',
		'9.2.2.4',
		'9.2.2.7',
		'9.2.2.8',
		'9.2.3',
		'9.2.3.3',
		'9.2.3.4',
		'9.2.4',
		'9.2.4.10',
		'9.2.4.13',
		'9.2.4.14',
		'9.2.4.16',
		'9.2.4.17',
		'9.2.4.18',
		'9.2.4.19',
		'9.2.4.2',
		'9.2.4.4',
		'9.2.4.8',
		'9.3.1.105',
		'9.3.1.50',
		'9.3.2.100',
		'9.3.2.243',
		'9.3.1',
		'9.3.1.1',
		'9.3.2',
		'9.3.2.2',
		'9.3.3',
		'9.3.3.1',
		'9.3.3.10',
		'9.3.3.11',
		'9.3.3.2',
		'9.3.3.5',
		'9.3.3.6',
		'9.3.3.9',
		'9.3.5',
		'9.4.0.115',
		'9.4.1',
		'9.4.1.1',
		'9.4.1.2',
		'9.4.1.3',
		'9.4.1.5',
		'9.4.2',
		'9.4.2.3',
		'9.4.3',
		'9.4.3.11',
		'9.4.3.12',
		'9.4.3.3',
		'9.4.3.4',
		'9.4.3.6',
		'9.4.3.8',
		'9.4.4',
		'9.4.4.1',
		'9.4.4.2',
		'9.4.4.3',
		'9.5.1',
		'9.5.2',
		'9.5.2.10',
		'9.5.2.14',
		'9.5.2.6',
		'9.5.3',
		'9.5.3.1',
		'9.5.3.2',
		'9.5.3.3',
		'9.5.3.6',
		'9.5.3.7',
		'9.6.0',
		'9.6.1',
		'9.6.1.10',
		'9.6.1.3',
		'9.6.1.5',
		'9.6.2',
		'9.6.2.1',
		'9.6.2.11',
		'9.6.2.2',
		'9.6.2.3',
		'9.6.2.7',
		'9.6.2.8',
		'9.6.2.9',
		'9.6.3',
		'9.6.3.1',
		'9.7.1',
		'9.7.1.1',
		'9.7.1.2');

foreach af (affected) {
  if (check_vers == af) {
    report = report_fixed_ver(installed_version: version, fixed_version: "See advisory");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);

