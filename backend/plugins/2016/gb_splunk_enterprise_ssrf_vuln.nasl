###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_splunk_enterprise_ssrf_vuln.nasl 12431 2018-11-20 09:21:00Z asteins $
#
# Splunk Enterprise Server-Side Request Forgery Vulnerability
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

CPE = 'cpe:/a:splunk:splunk';

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106472");
  script_version("$Revision: 12431 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-20 10:21:00 +0100 (Tue, 20 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-12-15 10:22:34 +0700 (Thu, 15 Dec 2016)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Splunk Enterprise Server-Side Request Forgery Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_splunk_detect.nasl");
  script_mandatory_keys("Splunk/installed");

  script_tag(name:"summary", value:"Splunk Enterprise is prone to a server-side request forgery (SSRF)
vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A server-side request forgery (SSRF) vulnerability exists in the Splunk
Enterprise web management interface within the Alert functionality. The application parses user supplied data in
the GET parameter 'alerts_id' to construct a HTTP request to the splunkd daemon. Since no validation is carried
out on the parameter, an attacker can specify an external domain and force the application to make a HTTP request
to an arbitrary destination host.");

  script_tag(name:"impact", value:"An attacker may exploit this via social engineering or other vectors to
exfiltrate administrative authentication tokens for the Splunk REST API to an external domain.");

  script_tag(name:"affected", value:"Splunk Enterprise 6.4.x, 6.3.x, 6.2.x, 6.1.x, 6.0.x and 5.0.x");

  script_tag(name:"solution", value:"Update to version 6.4.4, 6.3.8, 6.2.12, 6.1.12, 6.0.13, 5.0.17 or later.");

  script_xref(name:"URL", value:"https://www.splunk.com/view/SP-CAAAPSR");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version =~ "^6\.4") {
  if (version_is_less(version: version, test_version: "6.4.4")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "6.4.4");
    security_message(port: port, data: report);
    exit(0);
  }
}

if (version =~ "^6\.3") {
  if (version_is_less(version: version, test_version: "6.3.8")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "6.3.8");
    security_message(port: port, data: report);
    exit(0);
  }
}


if (version =~ "^6\.2") {
  if (version_is_less(version: version, test_version: "6.2.12")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "6.2.12");
    security_message(port: port, data: report);
    exit(0);
  }
}

if (version =~ "^6\.1") {
  if (version_is_less(version: version, test_version: "6.1.12")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "6.1.12");
    security_message(port: port, data: report);
    exit(0);
  }
}

if (version =~ "^6\.0") {
  if (version_is_less(version: version, test_version: "6.0.13")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "6.0.13");
    security_message(port: port, data: report);
    exit(0);
  }
}

if (version_is_less(version: version, test_version: "5.0.17")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.0.17");
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
