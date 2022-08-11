##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_trend_micro_interscan_web_security_virtual_appliance_cp1746.nasl 12106 2018-10-26 06:33:36Z cfischer $
#
# Trend Micro InternScan Web Security Virtual Appliance 6.5 Multiple Vulnerabilities
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

CPE = "cpe:/a:trendmicro:interscan_web_security_virtual_appliance";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106708");
  script_version("$Revision: 12106 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-03-31 09:02:03 +0700 (Fri, 31 Mar 2017)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");

  script_tag(name:"qod_type", value:"package");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Trend Micro InternScan Web Security Virtual Appliance 6.5 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_trend_micro_interscan_web_security_virtual_appliance_version.nasl");
  script_mandatory_keys("IWSVA/version", "IWSVA/build");

  script_tag(name:"summary", value:"Trend Micro has released a Critical Patch for Trend Micro InterScan Web
Security Virtual Appliance (IWSVA) 6.5.  This CP resolves multiple vulnerabilities in the product that could
potentially allow a remote attacker to execute artibtrary code on vulnerable installations.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Trend Micro InterScan Web Security Virtual Appliance (IWSVA) is prone to
multiple vulnerabilities:

  - Command Injection Remote Command Execution (RCE)

  - Directory Traversal

  - Privilege Escalation

  - Authentication Bypass

  - Information Disclosure

  - Stored Cross-Site Scripting (XSS)");

  script_tag(name:"affected", value:"Version 6.5");

  script_tag(name:"solution", value:"Update to version 6.5 CP 1746 or newer.");

  script_xref(name:"URL", value:"https://success.trendmicro.com/solution/1116960");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE))
  exit(0);

if (!build = get_kb_item("IWSVA/build"))
  exit(0);

if (version == "6.5" && int(build) < 1746) {
  report = report_fixed_ver(installed_version: version, installed_build: build,
                            fixed_version: "6.5", fixed_build: "1746");
  security_message(port: 0, data: report);
  exit(0);
}

exit(0);
