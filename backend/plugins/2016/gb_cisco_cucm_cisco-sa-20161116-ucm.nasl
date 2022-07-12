###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_cucm_cisco-sa-20161116-ucm.nasl 12096 2018-10-25 12:26:02Z asteins $
#
# Cisco Unified Communications Manager Web Interface Cross-Site Scripting Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.106395");
  script_version("$Revision: 12096 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-25 14:26:02 +0200 (Thu, 25 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-11-17 11:58:02 +0700 (Thu, 17 Nov 2016)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2016-6472");

  script_tag(name:"qod_type", value:"package");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Cisco Unified Communications Manager Web Interface Cross-Site Scripting Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("CISCO");
  script_dependencies("gb_cisco_cucm_version.nasl");
  script_mandatory_keys("cisco/cucm/version");

  script_tag(name:"summary", value:"A vulnerability in several parameters of the ccmivr page of Cisco Unified
Communication Manager (CallManager) could allow an unauthenticated, remote attacker to launch a cross-site
scripting (XSS) attack against a user of the web interface on the affected system.");

  script_tag(name:"insight", value:"The vulnerability is due to insufficient input validation of some
parameters used by that page. An attacker could exploit this vulnerability by convincing the user of the system
to follow an attacker-supplied link.");

  script_tag(name:"impact", value:"An exploit could allow the attacker to cause arbitrary script or HTML code
to be executed on the user's browser within the context of the affected application.");

  script_tag(name:"affected", value:"Cisco Unified Communications Manager version 11.5(1.2)");

  script_tag(name:"solution", value:"Cisco has released software updates that address this vulnerability.");

  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20161116-ucm");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

version = str_replace(string: version, find: "-", replace: ".");

if (version == "11.5.1.2") {
  report = report_fixed_ver(installed_version: version, fixed_version: 'See vendor advisory.');
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
