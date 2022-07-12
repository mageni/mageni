###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_moxa_iologik_e1200_series_mult_vuln.nasl 12363 2018-11-15 09:51:15Z asteins $
#
# Moxa ioLogik E1200 Series Multiple Vulnerabilities
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106360");
  script_version("$Revision: 12363 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-15 10:51:15 +0100 (Thu, 15 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-10-31 13:26:41 +0700 (Mon, 31 Oct 2016)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2016-8359", "CVE-2016-8372", "CVE-2016-8379", "CVE-2016-8350");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Moxa ioLogik E1200 Series Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_moxa_iologik_devices_detect.nasl");
  script_mandatory_keys("moxa_iologik/detected");

  script_tag(name:"summary", value:"Moxa ioLogik E1200 Series are prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Moxa ioLogik E1200 Series are prone to multiple vulnerabilities:

  - XSS: The web application fails to sanitize user input, which may allow an attacker to inject script or execute
arbitrary code. (CVE-2016-8359)

  - Insufficiently protected credentials: A password is transmitted in a format that is not sufficiently secure.
(CVE-2016-8372)

  - Weak password requirement: Users are restricted to using short passwords. (CVE-2016-8379)

  - CSRF: The web application may not sufficiently verify whether a request was provided by a valid user.
(CVE-2016-8350)");

  script_tag(name:"impact", value:"An attacker who exploits these vulnerabilities may be able to remotely
execute arbitrary code, modify parameters and settings, or reset the device.");

  script_tag(name:"affected", value:"Moxa ioLogik E1200 Series.");

  script_tag(name:"solution", value:"Update the Firmware.");

  script_xref(name:"URL", value:"https://ics-cert.us-cert.gov/advisories/ICSA-16-287-05");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

model = get_kb_item("moxa_iologik/model");
if (model !~ "^E12")
  exit(0);

if (!port = get_app_port(cpe: 'cpe:/a:moxa:iologik_' + tolower(model)))
  exit(0);

version = get_kb_item("moxa_iologik/fw_version");
if (!version)
  exit(0);

if (model =~ "E12(10|12|14|41|42|60|62)")
  if (version_is_less(version: version, test_version: "2.5")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2.5");
    security_message(port: port, data: report);
    exit(0);
  }

if (model =~ "E12(11|40)")
  if (version_is_less(version: version, test_version: "2.4")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2.4");
    security_message(port: port, data: report);
    exit(0);
  }

if (model == "E1213")
  if (version_is_less(version: version, test_version: "2.6")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2.6");
    security_message(port: port, data: report);
    exit(0);
  }

exit(0);
