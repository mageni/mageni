###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_nx_os_cisco-sa-20170517-nss.nasl 12106 2018-10-26 06:33:36Z cfischer $
#
# Cisco Nexus 5000 Series Switches CLI Command Injection Vulnerability
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

CPE = "cpe:/o:cisco:nx-os";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106812");
  script_cve_id("CVE-2017-6649");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_version("$Revision: 12106 $");

  script_name("Cisco Nexus 5000 Series Switches CLI Command Injection Vulnerability");

  script_xref(name:"URL", value:"https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170517-nss");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_tag(name:"summary", value:"A vulnerability in the CLI of Cisco NX-OS System Software running on Cisco
Nexus 5000 Series Switches could allow an authenticated, local attacker to perform a command injection attack.");

  script_tag(name:"insight", value:"The vulnerability is due to insufficient input validation of command
arguments. An attacker could exploit this vulnerability by injecting crafted command arguments into a vulnerable
CLI command.");

  script_tag(name:"impact", value:"An exploit could allow the attacker to read or write arbitrary files at the
user's privilege level outside of the user's path.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-05-18 09:43:14 +0700 (Thu, 18 May 2017)");
  script_category(ACT_GATHER_INFO);
  script_family("CISCO");
  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_dependencies("gb_cisco_nx_os_version.nasl");
  script_mandatory_keys("cisco_nx_os/version", "cisco_nx_os/model", "cisco_nx_os/device");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

device = get_kb_item("cisco_nx_os/device");
if (!device || "Nexus" >!< device)
  exit(0);

model = get_kb_item("cisco_nx_os/model");
if (!model || model !~ "^(3|35|5|6|7|9)[0-9]+")
  exit(0);

if (!version = get_app_version(cpe:CPE))
  exit(0);

affected = make_list(
		'7.1(1)N1(1)',
		'7.1(2)N1(1)',
		'7.1(3)N1(1)',
		'7.1(3)N1(2)',
		'7.1(3)N1(2.1)',
		'7.1(3)N1(3.12)',
		'7.1(4)N1(1)',
		'7.2(0)D1(0.437)',
		'7.2(0)N1(1)',
		'7.2(0)ZZ(99.1)',
		'7.2(1)N1(1)',
		'7.3(0)N1(1)');

foreach af (affected) {
  if (version == af) {
    report = report_fixed_ver(installed_version: version, fixed_version: "See advisory");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);

