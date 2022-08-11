###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_moxa_miineport_mult_vuln.nasl 12096 2018-10-25 12:26:02Z asteins $
#
# Moxa MiiNePort Multiple Vulnerabilities
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

CPE = 'cpe:/a:moxa:miineport';

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106468");
  script_version("$Revision: 12096 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-25 14:26:02 +0200 (Thu, 25 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-12-13 08:40:04 +0700 (Tue, 13 Dec 2016)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_cve_id("CVE-2016-9344", "CVE-2016-9346");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Moxa MiiNePort Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_moxa_miineport_telnet_detect.nasl");
  script_mandatory_keys("moxa/miineport/detected", "moxa/miineport/model");

  script_tag(name:"summary", value:"Moxa MiiNePort is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Moxa MiiNePort is prone to multiple vulnerabilities:

  - Active session brute force. (CVE-2016-9344)

  - Cleartext storage of sensitive information. (CVE-2016-9346)");

  script_tag(name:"impact", value:"An attacker may be able to brute force an active session cookie to be able
to download configuration files or read unencrypted sensitive data.");

  script_tag(name:"affected", value:"MiiNePort E1 versions prior to 1.8, MiiNePort E2 versions prior to 1.4 and
MiiNePort E3 versions prior to 1.1.");

  script_tag(name:"solution", value:"Upgrade the firmware to 1.8, 1, 4 or 1.1 depending on the model.");

  script_xref(name:"URL", value:"https://ics-cert.us-cert.gov/advisories/ICSA-16-343-01");
  script_xref(name:"URL", value:"http://www.moxa.com/support/download.aspx?type=support&id=1214");
  script_xref(name:"URL", value:"http://www.moxa.com/support/download.aspx?type=support&id=263");
  script_xref(name:"URL", value:"http://www.moxa.com/support/download.aspx?type=support&id=2058");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

model = get_kb_item("moxa/miineport/model");
if (!model)
  exit(0);

if (model == "E1") {
  if (version_is_less(version: version, test_version: "1.8")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "1.8");
    security_message(port: 0, data: report);
  }
  exit(0);
}

if (model == "E2") {
  if (version_is_less(version: version, test_version: "1.4")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "1.4");
    security_message(port: 0, data: report);
  }
  exit(0);
}

if (model == "E3") {
  if (version_is_less(version: version, test_version: "1.1")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "1.1");
    security_message(port: 0, data: report);
  }
  exit(0);
}

exit(0);
