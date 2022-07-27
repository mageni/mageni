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

CPE = "cpe:/a:livezilla:livezilla";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.142531");
  script_version("2019-07-02T04:48:50+0000");
  script_tag(name:"last_modification", value:"2019-07-02 04:48:50 +0000 (Tue, 02 Jul 2019)");
  script_tag(name:"creation_date", value:"2019-07-02 04:43:32 +0000 (Tue, 02 Jul 2019)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2019-12962", "CVE-2019-12963", "CVE-2019-12964");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("LiveZilla < 8.0.1.2 Multiple XSS Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_livezilla_detect.nasl");
  script_mandatory_keys("LiveZilla/installed");

  script_tag(name:"summary", value:"LiveZilla is prone to multiple cross-site scripting vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"LiveZilla is prone to multiple cross-site scripting vulnerabilities:

  - XSS vulnerability in mobile/index.php via the Accept-Language HTTP header (CVE-2019-12962)

  - XSS vulnerability in the chat.php Create Ticket Action (CVE-2019-12963)

  - XSS vulnerability in the ticket.php Subject (CVE-2019-12964)");

  script_tag(name:"affected", value:"LiveZilla version 8.0.1.1 and probably prior.");

  script_tag(name:"solution", value:"Update to version 8.0.1.2 or later.");

  script_xref(name:"URL", value:"https://forums.livezilla.net/index.php?/topic/10984-fg-vd-19-083085087-livezilla-server-are-vulnerable-to-cross-site-scripting-in-admin-panel/");
  script_xref(name:"URL", value:"https://forums.livezilla.net/index.php?/topic/10984-fg-vd-19-083085087-livezilla-server-are-vulnerable-to-cross-site-scripting-in-admin-panel/");
  script_xref(name:"URL", value:"https://forums.livezilla.net/index.php?/topic/10984-fg-vd-19-083085087-livezilla-server-are-vulnerable-to-cross-site-scripting-in-admin-panel/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos['version'];
location = infos['location'];

if (version_is_less(version: version, test_version: "8.0.1.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.0.1.2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
