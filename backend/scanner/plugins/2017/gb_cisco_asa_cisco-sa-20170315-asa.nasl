###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_asa_cisco-sa-20170315-asa.nasl 12106 2018-10-26 06:33:36Z cfischer $
#
# Cisco Adaptive Security Appliance BGP Bidirectional Forwarding Detection ACL Bypass Vulnerability
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

CPE = "cpe:/a:cisco:asa";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106654");
  script_cve_id("CVE-2017-3867");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_version("$Revision: 12106 $");

  script_name("Cisco Adaptive Security Appliance BGP Bidirectional Forwarding Detection ACL Bypass Vulnerability");

  script_xref(name:"URL", value:"https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170315-asa");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_tag(name:"summary", value:"A vulnerability in the Border Gateway Protocol (BGP) Bidirectional
Forwarding Detection (BFD) implementation of Cisco Adaptive Security Appliance (ASA) Software could allow an
unauthenticated, remote attacker to bypass the access control list (ACL) for specific TCP and UDP traffic.");

  script_tag(name:"insight", value:"The vulnerability occurs because the BFD implementation incorrectly allows
traffic with destination ports 3784 and 3785 through the interface ACLs.");

  script_tag(name:"impact", value:"An attacker could exploit this vulnerability by sending TCP or UDP packets
with a destination port of 3784 or 3785 through the ASA.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-03-16 09:23:08 +0700 (Thu, 16 Mar 2017)");
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
		'9.6.2',
		'9.6.2.1',
		'9.6.2.2',
		'9.6.2.3',
		'9.6.2.7',
		'9.6.2.8',
		'9.6.2.9',
		'9.6.3',
		'9.6.3.1');

foreach af (affected) {
  if (check_vers == af) {
    report = report_fixed_ver(installed_version: version, fixed_version: "See advisory");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);

