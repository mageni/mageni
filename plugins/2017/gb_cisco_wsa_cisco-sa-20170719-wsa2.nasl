###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_wsa_cisco-sa-20170719-wsa2.nasl 12106 2018-10-26 06:33:36Z cfischer $
#
# Cisco Web Security Appliance Authenticated Command Injection and Privilege Escalation Vulnerability
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

CPE = "cpe:/h:cisco:web_security_appliance";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106972");
  script_cve_id("CVE-2017-6748");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_version("$Revision: 12106 $");

  script_name("Cisco Web Security Appliance Authenticated Command Injection and Privilege Escalation Vulnerability");

  script_xref(name:"URL", value:"https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170719-wsa2");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_tag(name:"summary", value:"A vulnerability in the CLI parser of the Cisco Web Security Appliance (WSA)
could allow an authenticated, local attacker to perform command injection and elevate privileges to root. The
attacker must authenticate with valid operator-level or administrator-level credentials.");

  script_tag(name:"insight", value:"The vulnerability is due to insufficient validation of user-supplied input in
the CLI parser. An attacker could exploit this vulnerability by authenticating to the affected device and
performing command injection over the CLI.");

  script_tag(name:"impact", value:"An exploit could allow the attacker to escape from the CLI subshell and
execute system-level commands on the underlying operating system as root.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-07-20 14:18:58 +0700 (Thu, 20 Jul 2017)");
  script_category(ACT_GATHER_INFO);
  script_family("CISCO");
  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_dependencies("gb_cisco_wsa_version.nasl");
  script_mandatory_keys("cisco_wsa/installed");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe:CPE))
  exit(0);

affected = make_list(
		'10.0.0-232',
		'10.0.0-233',
		'10.1.0',
		'10.1.0-204',
		'10.1.1-230',
		'10.5.0',
		'10.5.0-358',
		'11.0.0',
		'11.0.0-613');

foreach af (affected) {
  if (version == af) {
    report = report_fixed_ver(installed_version: version, fixed_version: "See advisory");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);

