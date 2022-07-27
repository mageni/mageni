#############################################################################
# OpenVAS Vulnerability Test
#
# Coship Wireless Router Password Reset Vulnerability
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2019 Greenbone Networks GmbH
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.141884");
  script_version("2019-04-05T06:55:01+0000");
  script_tag(name:"last_modification", value:"2019-04-05 06:55:01 +0000 (Fri, 05 Apr 2019)");
  script_tag(name:"creation_date", value:"2019-01-17 13:02:49 +0700 (Thu, 17 Jan 2019)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2019-6441");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"NoneAvailable");

  script_name("Coship Wireless Router Password Reset Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_coship_router_snmp_detect.nasl");
  script_mandatory_keys("coship_router/detected");

  script_tag(name:"summary", value:"Coship Wireless Routers are prone to an unauthenticated admin password
reset.");

  script_tag(name:"affected", value:"Coship RT3052 - 4.0.0.48, Coship RT3050 - 4.0.0.40, Coship WM3300 - 5.0.0.54,
Coship WM3300 - 5.0.0.55, Coship RT7620 - 10.0.0.49 and probably prior versions.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"No known solution is available as of 29th March, 2019.
  Information regarding this issue will be updated once solution details are available.");

  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/151202/Coship-Wireless-Router-Unauthenticated-Admin-Password-Reset.html");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

cpe_list = make_list("cpe:/h:coship:rt3052",
                     "cpe:/h:coship:rt3050",
                     "cpe:/h:coship:wm3300",
                     "cpe:/h:coship:rt7620");

if (!infos = get_all_app_ports_from_list(cpe_list: cpe_list))
  exit(0);

cpe  = infos["cpe"];

if (!version = get_app_version(cpe: cpe, nofork: TRUE))
  exit(0);

if (cpe == "cpe:/h:coship:rt3052") {
  if (version_is_less_equal(version: version, test_version: "4.0.0.48")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "None");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/h:coship:rt3050") {
  if (version_is_less_equal(version: version, test_version: "4.0.0.40")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "None");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/h:coship:wm3300") {
  if (version_is_less_equal(version: version, test_version: "5.0.0.55")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "None");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/h:coship:rt7620") {
  if (version_is_less_equal(version: version, test_version: "10.0.0.49")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "None");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(0);
