###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_iox_cisco-sa-20161207-caf.nasl 12051 2018-10-24 09:14:54Z asteins $
#
# Cisco IOx Application-Hosting Framework Directory Traversal Vulnerability
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

CPE = "cpe:/a:cisco:iox";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106466");
  script_cve_id("CVE-2016-9199");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:N/A:N");
  script_version("$Revision: 12051 $");

  script_name("Cisco IOx Application-Hosting Framework Directory Traversal Vulnerability");

  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20161207-caf");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"Update to version 1.2.0.0");

  script_tag(name:"summary", value:"A vulnerability in the Cisco application-hosting framework (CAF) of Cisco
IOx could allow an authenticated, remote attacker to read arbitrary files on a targeted system.");

  script_tag(name:"insight", value:"The vulnerability is due to insufficient input validation by the affected
framework. An attacker could exploit this vulnerability by submitting specific, crafted input to the affected
framework on a targeted system.");

  script_tag(name:"impact", value:"A successful exploit could allow the attacker to read arbitrary files on the
targeted system.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"$Date: 2018-10-24 11:14:54 +0200 (Wed, 24 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-12-12 14:57:52 +0700 (Mon, 12 Dec 2016)");
  script_category(ACT_GATHER_INFO);
  script_family("CISCO");
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("gb_cisco_iox_web_detect.nasl");
  script_mandatory_keys("cisco_iox/installed");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, service: "www"))
  exit(0);

if (version == '1.1.0.0') {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.2.0.0");
  security_message(port: 0, data: report);
  exit(0);
}

exit( 99 );

