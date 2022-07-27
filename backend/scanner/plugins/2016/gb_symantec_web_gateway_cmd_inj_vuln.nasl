###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_symantec_web_gateway_cmd_inj_vuln.nasl 12096 2018-10-25 12:26:02Z asteins $
#
# Symantec Web Gateway OS Command Injection Vulnerability
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

CPE = "cpe:/a:symantec:web_gateway";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106342");
  script_version("$Revision: 12096 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-25 14:26:02 +0200 (Thu, 25 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-10-07 10:41:48 +0700 (Fri, 07 Oct 2016)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");

  script_cve_id("CVE-2016-5313");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Symantec Web Gateway OS Command Injection Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_symantec_web_gateway_detect.nasl");
  script_mandatory_keys("symantec_web_gateway/installed");

  script_tag(name:"summary", value:"Symantec Web Gateway is prone to a OS command injection vulnerability.");

  script_tag(name:"insight", value:"The vulnerable code is located in the /spywall/new_whitelist.php script.
The vulnerability exists because the validation checks may be bypassed by setting the 'sid' POST parameter to a
value different from zero. In this way, even though the 'white_ip' POST parameter is not a valid domain or IP
address, it will be passed to the add_whitelist() function as its $url parameter.");

  script_tag(name:"impact", value:"An authenticated attacker may execute arbitrary OS commands with the
privileges of the root user of the appliance.");

  script_tag(name:"affected", value:"Symantec Web Gateway version 5.2.2 and prior.");

  script_tag(name:"solution", value:"Update to version 5.2.5 or later.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "5.2.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.2.5");
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
