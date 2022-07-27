# Copyright (C) 2019 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) of the respective author(s)
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

CPE = 'cpe:/a:digium:asterisk';

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.143164");
  script_version("2019-11-22T03:30:14+0000");
  script_tag(name:"last_modification", value:"2019-11-22 03:30:14 +0000 (Fri, 22 Nov 2019)");
  script_tag(name:"creation_date", value:"2019-11-22 03:26:51 +0000 (Fri, 22 Nov 2019)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:C");

  script_cve_id("CVE-2019-18976");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Asterisk DoS Vulnerability (AST-2019-008)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("secpod_asterisk_detect.nasl");
  script_mandatory_keys("Asterisk-PBX/Installed");

  script_tag(name:"summary", value:"Asterisk is prone to a denial of service vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"If Asterisk receives a re-invite initiating T.38 faxing and has a port of 0
  and no c line in the SDP, a crash will occur.");

  script_tag(name:"affected", value:"Asterisk Open Source 13.x and 13.21 Certified Asterisk.");

  script_tag(name:"solution", value:"Upgrade to Version 13.29.2, 13.21-cert5 or later.");

  script_xref(name:"URL", value:"https://downloads.asterisk.org/pub/security/AST-2019-008.html");

  exit(0);
}

include("host_details.inc");
include("revisions-lib.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version =~ "^13\.") {
  if (version =~ "^13\.21cert") {
    if (revcomp(a: version, b: "13.21cert5") < 0) {
      report = report_fixed_ver(installed_version: version, fixed_version: "13.21-cert5");
      security_message(port: port, data: report, proto: "udp");
      exit(0);
    }
  }
  else {
    if (version_is_less(version: version, test_version: "13.29.2")) {
      report = report_fixed_ver(installed_version: version, fixed_version: "13.29.2");
      security_message(port: port, data: report, proto: "udp");
      exit(0);
    }
  }
}

exit(99);
