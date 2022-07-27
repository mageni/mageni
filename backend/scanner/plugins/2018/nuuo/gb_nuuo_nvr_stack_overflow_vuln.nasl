###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_nuuo_nvr_stack_overflow_vuln.nasl 12681 2018-12-06 04:47:43Z ckuersteiner $
#
# NUUO NVRmini2 < 3.10.0 Remote Stack Overflow Vulnerability
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

CPE = "cpe:/a:nuuo:nuuo";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.141762");
  script_version("$Revision: 12681 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-06 05:47:43 +0100 (Thu, 06 Dec 2018) $");
  script_tag(name:"creation_date", value:"2018-12-06 11:32:59 +0700 (Thu, 06 Dec 2018)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2018-19864");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("NUUO NVRmini2 < 3.10.0 Remote Stack Overflow Vulnerability");

  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_nuuo_devices_web_detect.nasl");
  script_mandatory_keys("nuuo/web/detected");

  script_tag(name:"summary", value:"NUUO NVRmini2 is prone to a unauthenticated remote stack overflow
vulnerability.");

  script_tag(name:"insight", value:"Sending a crafted GET request to the affected service with a URI length of 351
or greater will trigger the stack overflow. Overflowing of the stack variable, which is intended to hold the
request data, results in the overwriting of stored return addresses, and with a properly crafted payload, can be
leveraged to achieve arbitrary code execution.");

  script_tag(name:"impact", value:"Remote, unauthenticated users can execute arbitrary code on the affected system
with root privileges.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"Update to version 3.10.0 or later.");

  script_xref(name:"URL", value:"https://www.digitaldefense.com/blog/zero-day-alerts/nuuo-firmware-disclosure/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "3.10.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.10.0");
  security_message(port: port, data: report);
  exit(0);
}
