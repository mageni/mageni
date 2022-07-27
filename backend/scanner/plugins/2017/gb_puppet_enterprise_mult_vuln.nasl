###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_puppet_enterprise_mult_vuln.nasl 12106 2018-10-26 06:33:36Z cfischer $
#
# Puppet Enterprise < 2016.4.5 / < 2017.2.1 Multiple Vulnerabilities
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

CPE = "cpe:/a:puppet:enterprise";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106929");
  script_version("$Revision: 12106 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-07-06 15:23:17 +0700 (Thu, 06 Jul 2017)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2017-2292", "CVE-2017-2293", "CVE-2017-2294", "CVE-2017-2295", "CVE-2017-2297");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Puppet Enterprise < 2016.4.5 / < 2017.2.1 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_puppet_enterprise_detect.nasl");
  script_mandatory_keys("puppet_enterprise/installed");

  script_tag(name:"summary", value:"Puppet Enterprise is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Puppet Enterprise is prone to multiple vulnerabilities:

  - MCollective Remote Code Execution Via YAML Deserialization (CVE-2017-2292)

  - MCollective Server Allows Installing Arbitrary Packages On Agents (CVE-2017-2293)

  - MCollective Private Keys Visible In PuppetDB (CVE-2017-2294)

  - Puppet Server Remote Code Execution Via YAML Deserialization (CVE-2017-2295)

  - Incorrect Credential Management with RBAC Tokens (CVE-2017-2297)");

  script_tag(name:"affected", value:"Puppet Enterprise prior to 2016.4.5, 2016.5.x, 2017.1.x.");

  script_tag(name:"solution", value:"Update to version 2016.4.5, 2017.2.1 or later.");

  script_xref(name:"URL", value:"https://puppet.com/security/cve/cve-2017-2292");
  script_xref(name:"URL", value:"https://puppet.com/security/cve/cve-2017-2293");
  script_xref(name:"URL", value:"https://puppet.com/security/cve/cve-2017-2294");
  script_xref(name:"URL", value:"https://puppet.com/security/cve/cve-2017-2295");
  script_xref(name:"URL", value:"https://puppet.com/security/cve/cve-2017-2297");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "2016.4.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2016.4.5");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version:"2016.5.0", test_version2: "2017.2.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2017.2.1");
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
