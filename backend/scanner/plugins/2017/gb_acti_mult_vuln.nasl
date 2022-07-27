###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_acti_mult_vuln.nasl 11874 2018-10-12 11:28:04Z mmartin $
#
# ACTi Cameras Multiple Vulnerabilities
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

CPE = "cpe:/a:acti:acti";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106649");
  script_version("$Revision: 11874 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 13:28:04 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-03-14 12:58:36 +0700 (Tue, 14 Mar 2017)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2017-3184", "CVE-2017-3185", "CVE-2017-3186");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("ACTi Cameras Multiple Vulnerabilities");

  script_category(ACT_ATTACK);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_acti_devices_detect.nasl");
  script_mandatory_keys("acti_device/detected");

  script_tag(name:"summary", value:"ACTi Cameras are prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Tries to access the factory reset page and checks the response.");

  script_tag(name:"insight", value:"ACTi Cameras are prone to multiple vulnerabilities:

  - Missing authentication for the factory reset page. (CVE-2017-3184)

  - The web application uses the GET method to process requests that contain sensitive information such as user
account name and password, which can expose that information through the browser's history, referrers, web logs,
and other sources. (CVE-2017-3185)

  - Device uses non-random default credentials across all devices. A remote attacker can take complete control of a
device using default admin credentials. (CVE-2017-3186)");

  script_tag(name:"affected", value:"ACTi devices including D, B, I, and E series models using firmware version
A1D-500-V6.11.31-AC");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_xref(name:"URL", value:"https://www.kb.cert.org/vuls/id/355151");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

if (dir == "/")
  dir = "";

url = dir + "/setup/setup_maintain_firmware-default.html";

if (http_vuln_check(port: port, url: url, pattern: "Factory Default", check_header: TRUE,
                    extra_check: "SETTING_FACTORY_DEFAULT_CONFIG")) {
  report = report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
