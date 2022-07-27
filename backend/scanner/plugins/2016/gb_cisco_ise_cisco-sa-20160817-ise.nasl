###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_ise_cisco-sa-20160817-ise.nasl 12096 2018-10-25 12:26:02Z asteins $
#
# Cisco Identity Services Engine Admin Dashboard Page Cross-Site Scripting Vulnerability
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

CPE = 'cpe:/a:cisco:identity_services_engine';

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106193");
  script_version("$Revision: 12096 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-25 14:26:02 +0200 (Thu, 25 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-08-19 15:42:28 +0700 (Fri, 19 Aug 2016)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2016-1485");

  script_tag(name:"qod_type", value:"package");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Cisco Identity Services Engine Admin Dashboard Page Cross-Site Scripting Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("CISCO");
  script_dependencies("gb_cisco_ise_version.nasl");
  script_mandatory_keys("cisco_ise/version", "cisco_ise/patch");

  script_tag(name:"summary", value:"A vulnerability in the web framework code of Cisco Identity Services
Engine (ISE) could allow an unauthenticated, remote attacker to conduct a cross-site scripting (XSS) attack.");

  script_tag(name:"insight", value:"The vulnerability is due to insufficient input validation of some
parameters passed to the web server. An attacker could exploit this vulnerability by convincing the user
to access a malicious link or by intercepting the user's request and injecting malicious code.");

  script_tag(name:"impact", value:"An exploit could allow the attacker to execute arbitrary script code in
the context of the affected site or allow the attacker to access sensitive browser-based information.");

  script_tag(name:"affected", value:"Cisco Identity Services Engine software release 1.3(0.876)");

  script_tag(name:"solution", value:"See the vendors advisory for solutions.");

  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160817-ise");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE))
  exit(0);

if (!patch = get_kb_item("cisco_ise/patch"))
  exit(0);

if (version == "1.3.0.876") {
  if (int(patch) <= 7) {
    report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: 'See advisory');
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(0);
