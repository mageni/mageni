###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_cucm_cisco-sa-20170315-ucm2.nasl 12106 2018-10-26 06:33:36Z cfischer $
#
# Cisco Unified Communications Manager Cross-Site Request Forgery Vulnerability
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

CPE = "cpe:/a:cisco:unified_communications_manager";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106661");
  script_cve_id("CVE-2017-3877");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_version("$Revision: 12106 $");

  script_name("Cisco Unified Communications Manager Cross-Site Request Forgery Vulnerability");

  script_xref(name:"URL", value:"https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170315-ucm2");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_tag(name:"summary", value:"A vulnerability in the web framework of Cisco Unified Communications Manager
(CallManager) could allow an unauthenticated, remote attacker to conduct a cross-site request forgery (CSRF)
attack against a user of the web interface of the affected software.");

  script_tag(name:"insight", value:"The vulnerability is due to insufficient CSRF protections implemented by the
affected software. An attacker could exploit this vulnerability by persuading a user of the web interface to
follow a malicious link.");

  script_tag(name:"impact", value:"A successful exploit could allow the attacker to submit arbitrary requests to the affected software via the user's web browser and with the user's privileges.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-03-16 12:06:46 +0700 (Thu, 16 Mar 2017)");
  script_category(ACT_GATHER_INFO);
  script_family("CISCO");
  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_dependencies("gb_cisco_cucm_version.nasl");
  script_mandatory_keys("cisco/cucm/version");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe:CPE))
  exit(0);

version = str_replace(string: version, find: "-", replace: ".");

if (version == '11.5.1.11007.2') {
  report = report_fixed_ver(installed_version: version, fixed_version: "See advisory");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);

