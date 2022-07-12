###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_ios_xe_cisco-sa-20170320-ani.nasl 12106 2018-10-26 06:33:36Z cfischer $
#
# Cisco IOS XE Software Autonomic Networking Infrastructure Registrar Denial of Service Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.106676");
  script_cve_id("CVE-2017-3849");
  script_tag(name:"cvss_base", value:"6.1");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:N/I:N/A:C");
  script_version("$Revision: 12106 $");

  script_name("Cisco IOS XE Software Autonomic Networking Infrastructure Registrar Denial of Service Vulnerability");

  script_xref(name:"URL", value:"https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170320-ani");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_tag(name:"summary", value:"A vulnerability in the Autonomic Networking Infrastructure (ANI) registrar
feature of Cisco IOS XE Software could allow an unauthenticated, adjacent attacker to cause a denial of service
(DoS) condition.");

  script_tag(name:"insight", value:"The vulnerability is due to incomplete input validation on certain crafted
packets. An attacker could exploit this vulnerability by sending a crafted autonomic network channel discovery
packet to a device that has all the following characteristics:

  - Running a Cisco IOS XE Software release that supports the ANI feature

  - Configured as an autonomic registrar

  - Has a whitelist configured");

  script_tag(name:"impact", value:"An exploit could allow the attacker to cause the affected device to reload.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-03-21 10:11:53 +0700 (Tue, 21 Mar 2017)");
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
		'3.10.0S',
		'3.10.1S',
		'3.10.1xbS',
		'3.10.2S',
		'3.10.2tS',
		'3.10.3S',
		'3.10.4S',
		'3.10.5S',
		'3.10.6S',
		'3.10.7S',
		'3.10.8S',
		'3.10.8aS',
		'3.11.0S',
		'3.11.1S',
		'3.11.2S',
		'3.11.3S',
		'3.11.4S',
		'3.12.0aS',
		'3.12.1S',
		'3.12.2S',
		'3.12.3S',
		'3.12.4S',
		'3.13.0S',
		'3.13.0aS',
		'3.13.1S',
		'3.13.2S',
		'3.13.2aS',
		'3.13.3S',
		'3.13.4S',
		'3.13.5S',
		'3.13.5aS',
		'3.13.6S',
		'3.13.6aS',
		'3.14.0S',
		'3.14.1S',
		'3.14.2S',
		'3.14.3S',
		'3.14.4S',
		'3.15.0S',
		'3.15.1S',
		'3.15.1cS',
		'3.15.2S',
		'3.15.3S',
		'3.15.4S',
		'3.16.0S',
		'3.16.0cS',
		'3.16.1S',
		'3.16.1aS',
		'3.16.2S',
		'3.16.2bS',
		'3.16.3S',
		'3.16.3aS',
		'3.16.4S',
		'3.16.4aS',
		'3.16.4bS',
		'3.16.4dS',
		'3.16.5S',
		'3.17.0S',
		'3.17.1S',
		'3.17.1aS',
		'3.17.2S',
		'3.17.3S',
		'3.18.0S',
		'3.18.0SP',
		'3.18.0aS',
		'3.18.1S',
		'3.18.1SP',
		'3.18.1aSP',
		'3.18.1bSP',
		'3.18.1cSP',
		'3.18.2S',
		'3.18.3vS',
		'3.7.0E',
		'3.7.1E',
		'3.7.2E',
		'3.7.3E',
		'3.7.4E',
		'3.7.5E',
		'3.8.0E',
		'3.8.1E',
		'3.8.2E',
		'3.8.3E',
		'3.9.0E',
		'3.9.1E');

foreach af (affected) {
  if (version == af) {
    report = report_fixed_ver(installed_version: version, fixed_version: "See advisory");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);

