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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.142397");
  script_version("2019-05-13T07:07:43+0000");
  script_tag(name:"last_modification", value:"2019-05-13 07:07:43 +0000 (Mon, 13 May 2019)");
  script_tag(name:"creation_date", value:"2019-05-13 07:06:38 +0000 (Mon, 13 May 2019)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2019-6318");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("HP Printers RCE Vulnerability (HPSBPI03610)");

  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_hp_printer_detect.nasl");
  script_mandatory_keys("hp_printer/installed");

  script_tag(name:"summary", value:"HP LaserJet Enterprise printers, HP PageWide Enterprise printers, HP LaserJet
  Managed printers, HP Officejet Enterprise printers have an insufficient solution bundle signature validation
  that potentially allows execution of arbitrary code.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Multiple HP LaserJet, HP PageWide, HP LaserJet and HP Officejet devices. See
  the referenced advisory for an extended list.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_xref(name:"URL", value:"https://support.hp.com/us-en/document/c06265454");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!model = get_kb_item("hp_model"))
  exit(0);

if (!fw_ver = get_kb_item("hp_fw_ver"))
  exit(0);

if (model =~ "^Color LaserJet CM4540 MFP") {
  if (version_is_less(version: fw_ver, test_version: "2309010_581401")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2309010_581401");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^Color LaserJet CP5525") {
  if (version_is_less(version: fw_ver, test_version: "2309010_581402")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2309010_581402");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^Color LaserJet M553") {
  if (version_is_less(version: fw_ver, test_version: "2309010_581409")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2309010_581409");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^Color LaserJet M552") {
  if (version_is_less(version: fw_ver, test_version: "2309010_581409")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2309010_581409");
    security_message(port: 0, data: report);
    exit(0);
  }
  else if (fw_ver =~ "^240" && version_is_less(version: fw_ver, test_version: "2407081_000601")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2407081_000601");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^Color LaserJet M651") {
  if (version_is_less(version: fw_ver, test_version: "2309010_581418")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2309010_581418");
    security_message(port: 0, data: report);
    exit(0);
  }
  else if (fw_ver =~ "^240" && version_is_less(version: fw_ver, test_version: "2407081_000585")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2407081_000585");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^Color LaserJet M65[23]") {
  if (version_is_less(version: fw_ver, test_version: "2407081_000586")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2407081_000586");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^Color LaserJet M750") {
  if (version_is_less(version: fw_ver, test_version: "2309010_581423")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2309010_581423");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^Color LaserJet M855") {
  if (version_is_less(version: fw_ver, test_version: "2309010_581419")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2309010_581419");
    security_message(port: 0, data: report);
    exit(0);
  }
  else if (fw_ver =~ "^240" && version_is_less(version: fw_ver, test_version: "2407081_0005895")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2407081_000589");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^Color LaserJet (Flow)?MFP M577") {
  if (version_is_less(version: fw_ver, test_version: "2309010_581408")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2309010_581408");
    security_message(port: 0, data: report);
    exit(0);
  }
  else if (fw_ver =~ "^240" && version_is_less(version: fw_ver, test_version: "2407081_000571")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2407081_000571");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^Color LaserJet (Flow)?MFP M680") {
  if (version_is_less(version: fw_ver, test_version: "2309010_581416")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2309010_581416");
    security_message(port: 0, data: report);
    exit(0);
  }
  else if (fw_ver =~ "^240" && version_is_less(version: fw_ver, test_version: "2407081_000591")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2407081_000591");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^Color LaserJet (Flow)?MFP M681") {
  if (version_is_less(version: fw_ver, test_version: "2407081_000578")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2407081_000578");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^Color LaserJet (Flow)?MFP M682") {
  if (version_is_less(version: fw_ver, test_version: "2407081_000578")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2407081_000578");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^Color LaserJet (Flow)?MFP M880z") {
  if (version_is_less(version: fw_ver, test_version: "2309010_581433")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2309010_581433");
    security_message(port: 0, data: report);
    exit(0);
  }
  else if (fw_ver =~ "^240" && version_is_less(version: fw_ver, test_version: "2407081_0005991")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2407081_000599");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^Color LaserJet E55040dw") {
  if (version_is_less(version: fw_ver, test_version: "2407081_000601")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2407081_000601");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^Color LaserJet E650(5|6)0") {
  if (version_is_less(version: fw_ver, test_version: "2407081_000586")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2407081_000586");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^Color LaserJet MFP E778(22|25|30)") {
  if (version_is_less(version: fw_ver, test_version: "2407081_000644")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2407081_000644");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^Color LaserJet (Flow)?MFP E57540") {
  if (version_is_less(version: fw_ver, test_version: "2407081_000571")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2407081_000571");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^Color LaserJet (Flow)?MFP E675(5|6)0") {
  if (version_is_less(version: fw_ver, test_version: "2407081_000578")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2407081_000578");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^Color LaserJet (Flow)?MFP E876(4|5|6)0") {
  if (version_is_less(version: fw_ver, test_version: "2407163_000224")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2407163_000224");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^LaserJet 500 color M551") {
  if (version_is_less(version: fw_ver, test_version: "2309010_581427")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2309010_581427");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^LaserJet 500 (Flow)?MFP M525") {
  if (version_is_less(version: fw_ver, test_version: "2309010_581414")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2309010_581414");
    security_message(port: 0, data: report);
    exit(0);
  }
  else if (fw_ver =~ "^240" && version_is_less(version: fw_ver, test_version: "2407081_000594")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2407081_000594");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^LaserJet 500 (Flow)?MFP M575") {
  if (version_is_less(version: fw_ver, test_version: "2309010_581424")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2309010_581424");
    security_message(port: 0, data: report);
    exit(0);
  }
  else if (fw_ver =~ "^240" && version_is_less(version: fw_ver, test_version: "2407081_000587")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2407081_000587");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^LaserJet 600 M60(1|2|3)") {
  if (version_is_less(version: fw_ver, test_version: "2309010_581425")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2309010_581425");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^LaserJet 700 color MFP M775") {
  if (version_is_less(version: fw_ver, test_version: "2309010_581426")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2309010_581426");
    security_message(port: 0, data: report);
    exit(0);
  }
  else if (fw_ver =~ "^240" && version_is_less(version: fw_ver, test_version: "2407081_000583")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2407081_000583");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^LaserJet 700 M712") {
  if (version_is_less(version: fw_ver, test_version: "2309010_581422")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2309010_581422");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^LaserJet Flow MFP M630") {
  if (version_is_less(version: fw_ver, test_version: "2309010_581400")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2309010_581400");
    security_message(port: 0, data: report);
    exit(0);
  }
  else if (fw_ver =~ "^240" && version_is_less(version: fw_ver, test_version: "2407081_000588")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2407081_000588");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^LaserJet Flow MFP M830") {
  if (version_is_less(version: fw_ver, test_version: "2309010_581432")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2309010_581432");
    security_message(port: 0, data: report);
    exit(0);
  }
  else if (fw_ver =~ "^240" && version_is_less(version: fw_ver, test_version: "2407081_000569")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2407081_000569");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^LaserJet M4555 MFP") {
  if (version_is_less(version: fw_ver, test_version: "2309010_581404")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2309010_581404");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^LaserJet M506") {
  if (version_is_less(version: fw_ver, test_version: "2309010_581411")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2309010_581411");
    security_message(port: 0, data: report);
    exit(0);
  }
  else if (fw_ver =~ "^240" && version_is_less(version: fw_ver, test_version: "2407081_000597")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2407081_000597");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^LaserJet M60(4|5|6)") {
  if (version_is_less(version: fw_ver, test_version: "2309010_581410")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2309010_581410");
    security_message(port: 0, data: report);
    exit(0);
  }
  else if (fw_ver =~ "^240" && version_is_less(version: fw_ver, test_version: "2407081_000593")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2407081_000593");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^LaserJet M60(7|8|9)") {
  if (version_is_less(version: fw_ver, test_version: "2407081_000596")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2407081_000596");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^LaserJet M806") {
  if (version_is_less(version: fw_ver, test_version: "2309010_581423")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2309010_581423");
    security_message(port: 0, data: report);
    exit(0);
  }
  else if (fw_ver =~ "^240" && version_is_less(version: fw_ver, test_version: "2407081_000574")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2407081_000574");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^LaserJet (Flow )?MFP M527") {
  if (version_is_less(version: fw_ver, test_version: "2309010_581407")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2309010_581407");
    security_message(port: 0, data: report);
    exit(0);
  }
  else if (fw_ver =~ "^240" && version_is_less(version: fw_ver, test_version: "2407081_000575")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2407081_000575");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^LaserJet (Flow )?MFP M63(1|2|3)") {
  if (version_is_less(version: fw_ver, test_version: "2407081_000592")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2407081_000592");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^LaserJet MFP M725") {
  if (version_is_less(version: fw_ver, test_version: "2309010_581420")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2309010_581420");
    security_message(port: 0, data: report);
    exit(0);
  }
  else if (fw_ver =~ "^240" && version_is_less(version: fw_ver, test_version: "2407081_000570")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2407081_000570");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^LaserJet E50045") {
  if (version_is_less(version: fw_ver, test_version: "2407081_000597")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2407081_000597");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^LaserJet MFP E52545") {
  if (version_is_less(version: fw_ver, test_version: "2407081_000575")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2407081_000575");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^LaserJet E600(5|6|7)5") {
  if (version_is_less(version: fw_ver, test_version: "2407150_040194")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2407150_040194");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^LaserJet E625(5|6|7)5") {
  if (version_is_less(version: fw_ver, test_version: "2407081_000592")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2407081_000592");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^LaserJet (Flow )?MFP E725(25|30|35)") {
  if (version_is_less(version: fw_ver, test_version: "2407081_000643")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2407081_000643");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^LaserJet (Flow )?MFP E825(4|5|6)0") {
  if (version_is_less(version: fw_ver, test_version: "2407163_000218")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2407163_000218");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^Officejet Color FlowMFP X585") {
  if (version_is_less(version: fw_ver, test_version: "2309010_581406")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2309010_581406");
    security_message(port: 0, data: report);
    exit(0);
  }
  else if (fw_ver =~ "^240" && version_is_less(version: fw_ver, test_version: "2407081_000567")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2407081_000567");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^Officejet Color X555") {
  if (version_is_less(version: fw_ver, test_version: "2309010_581403")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2309010_581403");
    security_message(port: 0, data: report);
    exit(0);
  }
  else if (fw_ver =~ "^240" && version_is_less(version: fw_ver, test_version: "2407081_000595")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2407081_000595");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^PageWide Color 755") {
  if (version_is_less(version: fw_ver, test_version: "2407081_000573")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2407081_000573");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^PageWide Color MFP 77(4|9)") {
  if (version_is_less(version: fw_ver, test_version: "2407163_000240")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2407163_000240");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^PageWide Color 556") {
  if (version_is_less(version: fw_ver, test_version: "2309010_581412")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2309010_581412");
    security_message(port: 0, data: report);
    exit(0);
  }
  else if (fw_ver =~ "^240" && version_is_less(version: fw_ver, test_version: "2407081_000598")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2407081_000598");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^PageWide Color 765") {
  if (version_is_less(version: fw_ver, test_version: "2407081_000573")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2407081_000573");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^PageWide Color (Flow )?MFP 586") {
  if (version_is_less(version: fw_ver, test_version: "2309010_581413")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2309010_581413");
    security_message(port: 0, data: report);
    exit(0);
  }
  else if (fw_ver =~ "^240" && version_is_less(version: fw_ver, test_version: "2407081_000584")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2407081_000584");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^PageWide Color (Flow )?MFP 78(0|5)") {
  if (version_is_less(version: fw_ver, test_version: "2407163_000211")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2407163_000211");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^PageWide Color E55650") {
  if (version_is_less(version: fw_ver, test_version: "2309010_581412")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2309010_581412");
    security_message(port: 0, data: report);
    exit(0);
  }
  else if (fw_ver =~ "^240" && version_is_less(version: fw_ver, test_version: "2407081_000598")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2407081_000598");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^PageWide Color (Flow )?MFP E58650(dn|z)") {
  if (version_is_less(version: fw_ver, test_version: "2309010_581413")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2309010_581413");
    security_message(port: 0, data: report);
    exit(0);
  }
  else if (fw_ver =~ "^240" && version_is_less(version: fw_ver, test_version: "2407081_000584")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2407081_000584");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^PageWide Color E75(160|250)") {
  if (version_is_less(version: fw_ver, test_version: "2407081_000573")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2407081_000573");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^PageWide Color P75250") {
  if (version_is_less(version: fw_ver, test_version: "2407081_000573")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2407081_000573");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^PageWide Color MFP P77440") {
  if (version_is_less(version: fw_ver, test_version: "2407163_000240")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2407163_000240");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^PageWide Color (Flow )?MFP E776(5|6)0") {
  if (version_is_less(version: fw_ver, test_version: "2407163_000211")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2407163_000211");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^PageWide Color Flow MFP E77660z") {
  if (version_is_less(version: fw_ver, test_version: "2407163_000211")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2407163_000211");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^PageWide Color MFP P779(4|5|6)0") {
  if (version_is_less(version: fw_ver, test_version: "2407163_000240")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2407163_000240");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^ScanJet Flow N9120 fn1") {
  if (version_is_less(version: fw_ver, test_version: "2309010_581403")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2309010_581403");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^ScanJet Flow N9120 fn2") {
  if (version_is_less(version: fw_ver, test_version: "2407081_000577")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2407081_000577");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);
