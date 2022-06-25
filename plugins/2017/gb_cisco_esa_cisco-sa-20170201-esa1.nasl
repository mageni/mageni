###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_esa_cisco-sa-20170201-esa1.nasl 12106 2018-10-26 06:33:36Z cfischer $
#
# Cisco Email Security Appliance Malformed MIME Header Filtering Bypass Vulnerability
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

CPE = "cpe:/h:cisco:email_security_appliance";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106555");
  script_cve_id("CVE-2017-3818");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_version("$Revision: 12106 $");

  script_name("Cisco Email Security Appliance Malformed MIME Header Filtering Bypass Vulnerability");

  script_xref(name:"URL", value:"https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170201-esa1");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_tag(name:"summary", value:"A vulnerability in the Multipurpose Internet Mail Extensions (MIME) scanner
of Cisco AsyncOS Software for Cisco Email Security Appliances (ESA) could allow an unauthenticated, remote
attacker to bypass configured user filters on the device.");

  script_tag(name:"insight", value:"The vulnerability is due to improper error handling of a malformed MIME
header in an email attachment. An attacker could exploit this vulnerability by sending an email with a crafted
MIME attachment.");

  script_tag(name:"impact", value:"A successful exploit could allow the attacker to bypass configured user
filters to drop the email. The malformed MIME headers may not be RFC compliant. However, some mail clients could
still allow users to access the attachment, which may not have been properly filtered by the device.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-02-02 12:14:35 +0700 (Thu, 02 Feb 2017)");
  script_category(ACT_GATHER_INFO);
  script_family("CISCO");
  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_dependencies("gb_cisco_esa_version.nasl");
  script_mandatory_keys("cisco_esa/installed");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe:CPE))
  exit(0);

if (version == "9.7.1-066") {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.8.0-092");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);

