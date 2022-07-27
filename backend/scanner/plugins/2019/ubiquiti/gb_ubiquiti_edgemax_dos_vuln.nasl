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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.143046");
  script_version("2019-10-24T04:37:58+0000");
  script_tag(name:"last_modification", value:"2019-10-24 04:37:58 +0000 (Thu, 24 Oct 2019)");
  script_tag(name:"creation_date", value:"2019-10-24 04:22:41 +0000 (Thu, 24 Oct 2019)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_cve_id("CVE-2019-16889");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Ubiquiti EdgeMAX < 2.0.3 DoS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_ubnt_discovery_protocol_detect.nasl");
  script_mandatory_keys("ubnt_discovery_proto/firmware");

  script_tag(name:"summary", value:"Ubiquiti EdgeMAX devices are prone to a denial of service vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Remote attackers may cause a denial of service (disk consumption) because
  *.cache files in /var/run/beaker/container_file/ are created when providing a valid length payload of 249
  characters or fewer to the beaker.session.id cookie in a GET header. The attacker can use a long series of
  unique session IDs.");

  script_tag(name:"solution", value:"Update to firmware 2.0.3 or later.");

  script_xref(name:"URL", value:"https://mjlanders.com/2019/07/28/resource-consumption-dos-on-edgemax-v1-10-6/");
  script_xref(name:"URL", value:"https://community.ui.com/releases/New-EdgeRouter-firmware-2-0-3-has-been-released-2-0-3/e8badd28-a112-4269-9fb6-ffe3fc0e1643");

  exit(0);
}

include("version_func.inc");

fw = get_kb_item("ubnt_discovery_proto/firmware");

if (!fw || (fw !~ "^EdgeRouter"))
  exit(0);

# EdgeRouter.ER-e100.v1.9.0.4901118.160804.1131
vers = eregmatch(pattern: "\.v([0-9]\.[0-9]\.[0-9])", string: fw);
if (isnull(vers[1]))
  exit(0);

version = vers[1];

if (version_is_less(version: version, test_version: "2.0.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.0.3",
                            extra: "Detected Firmware Version (Full):  " + fw);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
