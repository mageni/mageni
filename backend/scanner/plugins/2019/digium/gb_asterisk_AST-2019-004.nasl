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
  script_oid("1.3.6.1.4.1.25623.1.0.142856");
  script_version("2019-09-06T05:10:55+0000");
  script_tag(name:"last_modification", value:"2019-09-06 05:10:55 +0000 (Fri, 06 Sep 2019)");
  script_tag(name:"creation_date", value:"2019-09-06 05:00:46 +0000 (Fri, 06 Sep 2019)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");

  script_cve_id("CVE-2019-15297");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Asterisk T.38 DoS Vulnerability (AST-2019-004)");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("secpod_asterisk_detect.nasl");
  script_mandatory_keys("Asterisk-PBX/Installed");

  script_tag(name:"summary", value:"Asterisk is prone to a denial of service vulnerability when negotiating for
  T.38 with a declined stream.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"When Asterisk sends a re-invite initiating T.38 faxing, and the endpoint
  responds with a declined media stream a crash will then occur in Asterisk.");

  script_tag(name:"affected", value:"Asterisk Open Source 15.x and 16.x.");

  script_tag(name:"solution", value:"Upgrade to Version 15.7.4, 16.5.1 or later.");

  script_xref(name:"URL", value:"https://downloads.asterisk.org/pub/security/AST-2019-004.html");

  exit(0);
}

include("host_details.inc");
include("revisions-lib.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version =~ "^15\.") {
  if (version_is_less(version: version, test_version: "15.7.4")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "15.7.4");
    security_message(port: port, data: report, proto: "udp");
    exit(0);
  }
}

if (version =~ "^16\.") {
  if (version_is_less(version: version, test_version: "16.5.1")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "16.5.1");
    security_message(port: port, data: report, proto: "udp");
    exit(0);
  }
}

exit(0);
