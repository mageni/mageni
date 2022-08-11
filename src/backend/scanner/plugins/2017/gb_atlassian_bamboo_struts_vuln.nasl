###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_atlassian_bamboo_struts_vuln.nasl 12106 2018-10-26 06:33:36Z cfischer $
#
# Atlassian Bamboo Struts2 RCE Vulnerability
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

CPE = "cpe:/a:atlassian:bamboo";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106652");
  script_version("$Revision: 12106 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-03-15 11:39:14 +0700 (Wed, 15 Mar 2017)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2017-5638");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Atlassian Bamboo Struts2 RCE Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_atlassian_bamboo_detect.nasl");
  script_mandatory_keys("AtlassianBamboo/Installed");

  script_tag(name:"summary", value:"Atlassian Bamboo is prone to a remote code execution vulnerability in
Struts2.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Bamboo uses a version of Struts 2 that is vulnerable to CVE-2017-5638.
Attackers can use this vulnerability to execute Java code of their choice on the system.");

  script_tag(name:"affected", value:"Atlassiona Bamboo 5.1 until 5.14.4, 5.15.0 until 5.15.2.");

  script_tag(name:"solution", value:"Update to 5.14.5, 5.15.3 or later.");

  script_xref(name:"URL", value:"https://jira.atlassian.com/browse/BAM-18242");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_in_range(version: version, test_version: "5.1.0", test_version2: "5.14.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.14.5");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "5.15.0", test_version2: "5.15.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.15.3");
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
