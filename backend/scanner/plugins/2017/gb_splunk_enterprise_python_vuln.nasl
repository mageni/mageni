###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_splunk_enterprise_python_vuln.nasl 12106 2018-10-26 06:33:36Z cfischer $
#
# Splunk Enterprise Python Vulnerabilities
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

CPE = 'cpe:/a:splunk:splunk';

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106539");
  script_version("$Revision: 12106 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-01-24 10:40:31 +0700 (Tue, 24 Jan 2017)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2016-5636", "CVE-2016-5699", "CVE-2016-0772");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Splunk Enterprise Python Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_splunk_detect.nasl");
  script_mandatory_keys("Splunk/installed");

  script_tag(name:"summary", value:"Splunk Enterprise is prone to multiple vulnerabilities in Python.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Splunk Enterprise is prone to multiple vulnerabilities in Python:

  - Integer overflow in the get_data function in zipimport.c in Python allows remote attackers to have unspecified
impact via a negative data size value, which triggers a heap-based buffer overflow. (CVE-2016-5636)

  - CRLF injection vulnerability in the HTTPConnection.putheader function in urllib2 and urllib in Python allows
remote attackers to inject arbitrary HTTP headers via CRLF sequences in a URL. (CVE-2016-5699)

  - The smtplib library in Python does not return an error when StartTLS fails, which might allow man-in-the-middle
attackers to bypass the TLS protections by leveraging a network position between the client and the registry to
block the StartTLS command, aka a 'StartTLS stripping attack'. (CVE-2016-0772)");

  script_tag(name:"affected", value:"Splunk Enterprise 5.0.x, 6.0.x, 6.1.x, 6.2.x, 6.3.x, 6.4.x and 6.5.0");

  script_tag(name:"solution", value:"Update to version 5.0.17, 6.0.13, 6.1.12, 6.2.12, 6.3.8, 6.4.5, 6.5.1 or
later.");

  script_xref(name:"URL", value:"https://www.splunk.com/view/SP-CAAAPSR");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version =~ "^5\.0") {
  if (version_is_less(version: version, test_version: "5.0.17")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "5.0.17");
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

if (version =~ "^6\.1") {
  if (version_is_less(version: version, test_version: "6.1.12")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "6.1.12");
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

if (version =~ "^6\.3") {
  if (version_is_less(version: version, test_version: "6.3.8")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "6.3.8");
    security_message(port: port, data: report);
    exit(0);
  }
}

if (version =~ "^6\.4") {
  if (version_is_less(version: version, test_version: "6.4.5")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "6.4.5");
    security_message(port: port, data: report);
    exit(0);
  }
}

if (version =~ "^6\.5") {
  if (version_is_less(version: version, test_version: "6.5.1")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "6.5.1");
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(0);
