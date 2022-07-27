# Copyright (C) 2019 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.142515");
  script_version("2019-06-28T04:56:03+0000");
  script_tag(name:"last_modification", value:"2019-06-28 04:56:03 +0000 (Fri, 28 Jun 2019)");
  script_tag(name:"creation_date", value:"2019-06-28 03:26:06 +0000 (Fri, 28 Jun 2019)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2018-5923");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("HP Printers RCE Vulnerability (HPSBPI03596)");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_hp_printer_detect.nasl");
  script_mandatory_keys("hp_printer/installed");

  script_tag(name:"summary", value:"Multiple HP printers are prone to a remote code execution vulnerability in
  the solution application signature checking.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"HP LaserJet Enterprise, HP PageWide Enterprise, HP LaserJet Managed, and
  HP OfficeJet Enterprise Printers.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_xref(name:"URL", value:"https://support.hp.com/us-en/document/c06169434");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!model = get_kb_item("hp_model"))
  exit(0);

if (!fw_ver = get_kb_item("hp_fw_ver"))
  exit(0);

if (model =~ "^Color LaserJet CM4540 MFP") {
  if (version_is_less(version: fw_ver, test_version: "2308974_579754")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2308974_579754");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^Color LaserJet CP5525") {
  if (version_is_less(version: fw_ver, test_version: "2308974_579753")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2308974_579753");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^Color LaserJet FlowMFP M681") {
  if (version_is_less(version: fw_ver, test_version: "2406087_000017")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2406087_000017");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^Color LaserJet FlowMFP M682") {
  if (version_is_less(version: fw_ver, test_version: "2406087_000017")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2406087_000017");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^Color LaserJet M552") {
  if (version_is_less(version: fw_ver, test_version: "2308974_579763")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2308974_579763");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^Color LaserJet M553") {
  if (version_is_less(version: fw_ver, test_version: "2308974_579763")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2308974_579763");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^Color LaserJet M651") {
  if (version_is_less(version: fw_ver, test_version: "2308974_579770")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2308974_579770");
    security_message(port: 0, data: report);
    exit(0);
  }
  else if (fw_ver =~ "^240" && version_is_less(version: fw_ver, test_version: "2406048_029632")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2406048_029632");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^Color LaserJet M65[23]") {
  if (version_is_less(version: fw_ver, test_version: "2406087_000016")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2406087_000016");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^Color LaserJet M750") {
  if (version_is_less(version: fw_ver, test_version: "2308974_579776")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2308974_579776");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^Color LaserJet (Flow)?MFP M577") {
  if (version_is_less(version: fw_ver, test_version: "2308974_579760")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2308974_579760");
    security_message(port: 0, data: report);
    exit(0);
  }
  else if (fw_ver =~ "^240" && version_is_less(version: fw_ver, test_version: "2406048_029627")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2406048_029627");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^Color LaserJet (Flow)?MFP M680") {
  if (version_is_less(version: fw_ver, test_version: "2308974_579771")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2308974_579771");
    security_message(port: 0, data: report);
    exit(0);
  }
  else if (fw_ver =~ "^240" && version_is_less(version: fw_ver, test_version: "2406048_029633")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2406048_029633");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^Color LaserJet E55040dw") {
  if (version_is_less(version: fw_ver, test_version: "2406048_029643")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2406048_029643");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^Color LaserJet E65050dn") {
  if (version_is_less(version: fw_ver, test_version: "2406087_000016")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2406087_000016");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^Color LaserJet E65060") {
  if (version_is_less(version: fw_ver, test_version: "2405130_000068")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2405130_000068");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^Color LaserJet (Flow)?MFP E57540") {
  if (version_is_less(version: fw_ver, test_version: "2406048_029627")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2406048_029627");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^Color LaserJet (Flow)?MFP E67550") {
  if (version_is_less(version: fw_ver, test_version: "2406087_000017")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2406087_000017");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^Color LaserJet (Flow)?MFP E67560") {
  if (version_is_less(version: fw_ver, test_version: "2406087_000017")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2406087_000017");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^Color LaserJet MFP E778(22|25|30)") {
  if (version_is_less(version: fw_ver, test_version: "2406048_029616")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2406048_029616");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^Color LaserJet MFP E876(40|50|60)") {
  if (version_is_less(version: fw_ver, test_version: "2406048_029615")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2406048_029615");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^Digital Sender Flow 8500 fn2") {
  if (version_is_less(version: fw_ver, test_version: "2308937_578483")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2308937_578483");
    security_message(port: 0, data: report);
    exit(0);
  }
  else if (fw_ver =~ "^240" && version_is_less(version: fw_ver, test_version: "2406048_029623")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2406048_029623");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^LaserJet 500 (Flow)?MFP M575") {
  if (version_is_less(version: fw_ver, test_version: "2308974_579774")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2308974_579774");
    security_message(port: 0, data: report);
    exit(0);
  }
  else if (fw_ver =~ "^240" && version_is_less(version: fw_ver, test_version: "2406048_029634")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2406048_029634");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^LaserJet 500 (Flow)?MFP M525") {
  if (version_is_less(version: fw_ver, test_version: "2308974_579765")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2308974_579765");
    security_message(port: 0, data: report);
    exit(0);
  }
  else if (fw_ver =~ "^240" && version_is_less(version: fw_ver, test_version: "2406048_029635")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2406048_029635");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^LaserJet 600 M60(1|2|3)") {
  if (version_is_less(version: fw_ver, test_version: "2308974_579777")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2308974_579777");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^LaserJet 700 color MFP M775") {
  if (version_is_less(version: fw_ver, test_version: "2308974_579779")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2308974_579779");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^LaserJet 700 M712") {
  if (version_is_less(version: fw_ver, test_version: "2308974_579775")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2308974_579775");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^Color LaserJet M855") {
  if (version_is_less(version: fw_ver, test_version: "2308974_579768")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2308974_579768");
    security_message(port: 0, data: report);
    exit(0);
  }
  else if (fw_ver =~ "^240" && version_is_less(version: fw_ver, test_version: "2406048_029621")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2406048_029621");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^Color LaserJet (Flow)?MFP M880z") {
  if (version_is_less(version: fw_ver, test_version: "2308974_579767")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2308974_579767");
    security_message(port: 0, data: report);
    exit(0);
  }
  else if (fw_ver =~ "^240" && version_is_less(version: fw_ver, test_version: "2406048_029641")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2406048_029641");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^LaserJet 500 color M551") {
  if (version_is_less(version: fw_ver, test_version: "2308974_579778")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2308974_579778");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^LaserJet Flow MFP M830") {
  if (version_is_less(version: fw_ver, test_version: "2308974_579769")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2308974_579769");
    security_message(port: 0, data: report);
    exit(0);
  }
  else if (fw_ver =~ "^240" && version_is_less(version: fw_ver, test_version: "2406048_029645")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2406048_029645");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^LaserJet Flow MFP M630") {
  if (version_is_less(version: fw_ver, test_version: "2308974_579755")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2308974_579755");
    security_message(port: 0, data: report);
    exit(0);
  }
  else if (fw_ver =~ "^240" && version_is_less(version: fw_ver, test_version: "2406048_029631")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2406048_029631");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^LaserJet (Flow )?MFP M63(1|2|3)") {
  if (version_is_less(version: fw_ver, test_version: "2406048_029629")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2406048_029629");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^LaserJet M60(4|5|6)") {
  if (version_is_less(version: fw_ver, test_version: "2308974_579762")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2308974_579762");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^LaserJet M60(7|8|9)") {
  if (version_is_less(version: fw_ver, test_version: "2406048_029638")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2406048_029638");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^LaserJet M806") {
  if (version_is_less(version: fw_ver, test_version: "2308974_579772")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2308974_579772");
    security_message(port: 0, data: report);
    exit(0);
  }
  else if (fw_ver =~ "^240" && version_is_less(version: fw_ver, test_version: "2406048_029646")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2406048_029646");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^LaserJet (Flow )?MFP M527") {
  if (version_is_less(version: fw_ver, test_version: "2308974_579761")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2308974_579761");
    security_message(port: 0, data: report);
    exit(0);
  }
  else if (fw_ver =~ "^240" && version_is_less(version: fw_ver, test_version: "2406048_029628")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2406048_029628");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^LaserJet MFP M725") {
  if (version_is_less(version: fw_ver, test_version: "2308974_579773")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2308974_579773");
    security_message(port: 0, data: report);
    exit(0);
  }
  else if (fw_ver =~ "^240" && version_is_less(version: fw_ver, test_version: "2406048_029644")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2406048_029644");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^LaserJet E50045") {
  if (version_is_less(version: fw_ver, test_version: "2406048_029640")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2406048_029640");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^LaserJet E600(5|6|7)5") {
  if (version_is_less(version: fw_ver, test_version: "2406048_029638")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2406048_029638");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^LaserJet MFP E52545") {
  if (version_is_less(version: fw_ver, test_version: "2406048_029628")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2406048_029628");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^LaserJet E625(5|6|7)5") {
  if (version_is_less(version: fw_ver, test_version: "2406048_029629")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2406048_029629");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^LaserJet (Flow )?MFP E725(25|30|35)") {
  if (version_is_less(version: fw_ver, test_version: "2406048_029614")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2406048_029614");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^LaserJet (Flow )?MFP E825(4|5|6)0") {
  if (version_is_less(version: fw_ver, test_version: "2406048_029617")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2406048_029617");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^Officejet Color FlowMFP X585") {
  if (version_is_less(version: fw_ver, test_version: "2308974_579759")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2308974_579759");
    security_message(port: 0, data: report);
    exit(0);
  }
  else if (fw_ver =~ "^240" && version_is_less(version: fw_ver, test_version: "2406048_029636")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2406048_029636");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^Officejet Color X555") {
  if (version_is_less(version: fw_ver, test_version: "2308974_579758")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2308974_579758");
    security_message(port: 0, data: report);
    exit(0);
  }
  else if (fw_ver =~ "^240" && version_is_less(version: fw_ver, test_version: "2406048_029642")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2406048_029642");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^PageWide Color 765") {
  if (version_is_less(version: fw_ver, test_version: "2406048_029619")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2406048_029619");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^PageWide Color (Flow )?MFP 586") {
  if (version_is_less(version: fw_ver, test_version: "2308974_579780")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2308974_579780");
    security_message(port: 0, data: report);
    exit(0);
  }
  else if (fw_ver =~ "^240" && version_is_less(version: fw_ver, test_version: "2406048_029624")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2406048_029624");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^PageWide Color (Flow )?MFP 78(0|5)") {
  if (version_is_less(version: fw_ver, test_version: "2406048_029621")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2406048_029621");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^PageWide Color X556") {
  if (version_is_less(version: fw_ver, test_version: "2308974_579766")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2308974_579766");
    security_message(port: 0, data: report);
    exit(0);
  }
  else if (fw_ver =~ "^240" && version_is_less(version: fw_ver, test_version: "2406048_029637")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2406048_029637");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^PageWide Color E75160") {
  if (version_is_less(version: fw_ver, test_version: "2406048_029619")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2406048_029619");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^PageWide Color (Flow )?MFP E58650") {
  if (version_is_less(version: fw_ver, test_version: "2308974_579780")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2308974_579780");
    security_message(port: 0, data: report);
    exit(0);
  }
  else if (fw_ver =~ "^240" && version_is_less(version: fw_ver, test_version: "2406048_029624")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2406048_029624");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^PageWide Color (Flow )?MFP E776(5|6)0") {
  if (version_is_less(version: fw_ver, test_version: "2406048_029621")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2406048_029621");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^Scanjet Enterprise 8500") {
  if (version_is_less(version: fw_ver, test_version: "2308974_579756")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2308974_579756");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^Scanjet Enterprise Flow N9120") {
  if (version_is_less(version: fw_ver, test_version: "2406048_029625")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2406048_029625");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);
