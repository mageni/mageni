##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_linksys_eseries_cmd_exec_vuln.nasl 13316 2019-01-28 07:41:51Z asteins $
#
# Linksys ESeries Multiple OS Command Injection Vulnerabilities
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2018 Greenbone Networks GmbH
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

CPE = "cpe:/a:linksys:devices";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.141621");
  script_version("$Revision: 13316 $");
  script_tag(name:"last_modification", value:"$Date: 2019-01-28 08:41:51 +0100 (Mon, 28 Jan 2019) $");
  script_tag(name:"creation_date", value:"2018-10-30 14:57:10 +0700 (Tue, 30 Oct 2018)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");

  script_cve_id("CVE-2018-3953", "CVE-2018-3954", "CVE-2018-3955");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Linksys ESeries Multiple OS Command Injection Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_linksys_devices_detect.nasl");
  script_mandatory_keys("Linksys/model", "Linksys/firmware");

  script_tag(name:"summary", value:"Linksys ESeries are prone to multiple authenticated OS command execution
vulnerabilities.");

  script_tag(name:"insight", value:"Specially crafted entries to network configuration information can cause
execution of arbitrary system commands, resulting in full control of the device. An attacker can send an
authenticated HTTP request to trigger this vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Linksys E1200 and E2500.");

  script_tag(name:"solution", value:"Update to firmware version 2.0.10 (E1200), 3.0.05 (E2500) or later.");

  script_xref(name:"URL", value:"https://blog.talosintelligence.com/2018/10/vulnerability-spotlight-linksys-eseries.html");
  script_xref(name:"URL", value:"https://talosintelligence.com/vulnerability_reports/TALOS-2018-0625");
  script_xref(name:"URL", value:"https://www.linksys.com/us/support-product?pid=01t80000003KRTzAAO");
  script_xref(name:"URL", value:"https://www.linksys.com/us/support-product?pid=01t80000003KZuNAAW");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!get_app_location(cpe:CPE, nofork:TRUE))
  exit(0);

model = get_kb_item("Linksys/model");
if (!model || (model !~ "^E(12|25)00"))
  exit(0);

if (!version = get_kb_item("Linksys/firmware"))
  exit(0);

check_vers = str_replace(string: version, find: " build ", replace: ".");

if (model == "E1200") {
  if (version_is_less(version: check_vers, test_version: "2.0.10.1")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2.0.10 build 1");
    security_message(port: 0, data: report);
    exit(0);
  }
}
else if (model == "E2500") {
  if (version_is_less(version: check_vers, test_version: "3.0.05.2")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "3.0.05 build 2");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);
