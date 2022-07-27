###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_cucm_cisco-sa-20161207-cur.nasl 12431 2018-11-20 09:21:00Z asteins $
#
# Cisco Unified Communications Manager Unified Reporting Upload Tool Directory Traversal Vulnerability
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

CPE = "cpe:/a:cisco:unified_communications_manager";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106442");
  script_version("$Revision: 12431 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-20 10:21:00 +0100 (Tue, 20 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-12-08 13:24:06 +0700 (Thu, 08 Dec 2016)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_cve_id("CVE-2016-9210");

  script_tag(name:"qod_type", value:"package");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Cisco Unified Communications Manager Unified Reporting Upload Tool Directory Traversal Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("CISCO");
  script_dependencies("gb_cisco_cucm_version.nasl");
  script_mandatory_keys("cisco/cucm/version");

  script_tag(name:"summary", value:"A vulnerability in the Cisco Unified Reporting upload tool accessed via
the Cisco Unified Communications Manager could allow an unauthenticated, remote attacker to modify arbitrary
files on the file system.");

  script_tag(name:"insight", value:"The vulnerability is due to insufficient client-side validation checks. An
attacker could exploit this vulnerability by submitting a malicious POST request to the affected system.");

  script_tag(name:"impact", value:"An exploit could allow the attacker to implant arbitrary files onto the
affected system.");

  script_tag(name:"affected", value:"Cisco Unified Communications Manager version 11.5(1.11007.2)");

  script_tag(name:"solution", value:"Cisco has released software updates that address this vulnerability.");

  script_xref(name:"URL", value:"https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20161207-cur");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

vers = str_replace( string:vers, find:"-", replace:"." );

if (version == "11.5.1.11007.2") {
  report = report_fixed_ver(installed_version: version, fixed_version: 'See vendor advisory.');
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
