##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_hp_printers_fax_rce_vuln.nasl 14156 2019-03-13 14:38:13Z cfischer $
#
# HP Ink Printers RCE Vulnerabilities (Faxploit)
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2018 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.141380");
  script_version("$Revision: 14156 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-13 15:38:13 +0100 (Wed, 13 Mar 2019) $");
  script_tag(name:"creation_date", value:"2018-08-17 10:33:30 +0700 (Fri, 17 Aug 2018)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2018-5924", "CVE-2018-5925");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("HP Ink Printers RCE Vulnerabilities (Faxploit)");

  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Gain a shell remotely");
  script_dependencies("gb_hp_printer_detect.nasl");
  script_mandatory_keys("hp_printer/installed");

  script_tag(name:"summary", value:"Two security vulnerabilities have been identified with certain HP Inkjet
printers. A maliciously crafted file sent to an affected device can cause a stack or static buffer overflow, which
could allow remote code execution.");

  script_tag(name:"vuldetect", value:"The script checks if the target host is a vulnerable device running a
vulnerable firmware version.");

  script_tag(name:"affected", value:"Multiple HP PageWide Pro, HP DesignJet, HP Officejet, HP Deskjet and HP Envy
devices. See the referenced advisory for an extended list.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_xref(name:"URL", value:"https://support.hp.com/us-en/document/c06097712");
  script_xref(name:"URL", value:"https://research.checkpoint.com/sending-fax-back-to-the-dark-ages/");
  script_xref(name:"URL", value:"https://blog.checkpoint.com/2018/08/12/faxploit-hp-printer-fax-exploit/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!model = get_kb_item("hp_model"))
  exit(0);

if (!fw_ver = get_kb_item("hp_fw_ver"))
  exit(0);

if (model =~ "^PageWide 352dw") {
  if (version_is_less(version: fw_ver, test_version: "ICEMDWPP1N001.1829A.00")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "ICEMDWPP1N001.1829A.00");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^PageWide MFP P57750") {
  if (version_is_less(version: fw_ver, test_version: "MAHDWOPP1N001.1829A.00")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "MAHDWOPP1N001.1829A.00");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^PageWide Managed MFP (P77740(dn|dw|z|P777(5|6)0z))") {
  if (version_is_less(version: fw_ver, test_version: "LIMOFWPP1N005.1828A.00")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "LIMOFWPP1N005.1828A.00");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^PageWide P55250dw") {
  if (version_is_less(version: fw_ver, test_version: "ICHDWOPP1N001.1829A.00")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "ICHDWOPP1N001.1829A.00");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^PageWide (Managed )?P75050(dn|dw)") {
  if (version_is_less(version: fw_ver, test_version: "LIMOFWPP1N005.1828A.00")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "LIMOFWPP1N005.1828A.00");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^PageWide 377dw") {
  if (version_is_less(version: fw_ver, test_version: "MAVEDWPP1N001.1829A.00")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "MAVEDWPP1N001.1829A.00");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^PageWide Pro 452dn") {
  if (version_is_less(version: fw_ver, test_version: "ICEMDNPP1N001.1829A.00")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "ICEMDNPP1N001.1829A.00");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^PageWide Pro 552dw") {
  if (version_is_less(version: fw_ver, test_version: "ICHDWOPP1N001.1829A.00")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "ICHDWOPP1N001.1829A.0");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^PageWide Pro 750(dn|dw)") {
  if (version_is_less(version: fw_ver, test_version: "LIMOFWPP1N005.1828A.00")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "LIMOFWPP1N005.1828A.00");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^PageWide Pro 477(dn|dw)") {
  if (version_is_less(version: fw_ver, test_version: "MAVEDNPP1N001.1829A.00")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "MAVEDNPP1N001.1829A.00");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^PageWide Pro 577") {
  if (version_is_less(version: fw_ver, test_version: "MAHDWOPP1N001.1829A.00")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "MAHDWOPP1N001.1829A.00");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^PageWide Pro MFP 772(dn|dw)") {
  if (version_is_less(version: fw_ver, test_version: "LIMOFWPP1N005.1828A.00")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "LIMOFWPP1N005.1828A.00");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^PageWide Pro 452dw") {
  if (version_is_less(version: fw_ver, test_version: "ICEMDWPP1N001.1829A.00")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "ICEMDWPP1N001.1829A.00");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^Officejet Pro X451(dn|dw)") {
  if (version_is_less(version: fw_ver, test_version: "BNP1CN1829BR")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "BNP1CN1829BR");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^Officejet Pro X476(dn|dw)") {
  if (version_is_less(version: fw_ver, test_version: "LNP1CN1829BR")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "LNP1CN1829BR");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^Officejet Pro X551dw") {
  if (version_is_less(version: fw_ver, test_version: "BZP1CN1829BR")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "BZP1CN1829BR");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^Officejet Pro X576dw") {
  if (version_is_less(version: fw_ver, test_version: "LZP1CN1829BR")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "LZP1CN1829BR");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^Designjet T120") {
  if (version_is_less(version: fw_ver, test_version: "AXP2CN1829BR")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "AXP2CN1829BR");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^Designjet T520") {
  if (version_is_less(version: fw_ver, test_version: "AXP2CN1829BR")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "AXP2CN1829BR");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^DesignJet T730") {
  if (version_is_less(version: fw_ver, test_version: "CANDELPR2N001.1829A.00")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "CANDELPR2N001.1829A.00");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^DesignJet T830") {
  if (version_is_less(version: fw_ver, test_version: "CANDELPR2N001.1829A.00")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "CANDELPR2N001.1829A.00");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^Deskjet 2540") {
  if (version_is_less(version: fw_ver, test_version: "CBP1FN1828BR")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "CBP1FN1828BR");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^Deskjet 2600") {
  if (version_is_less(version: fw_ver, test_version: "TJP1FN1828AR")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "TJP1FN1828AR");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^Deskjet Ink Advantage 3540") {
  if (version_is_less(version: fw_ver, test_version: "MLM1FN1828AR")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "MLM1FN1828AR");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^DeskJet 3630") {
  if (version_is_less(version: fw_ver, test_version: "SWP2FN1829AR")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "SWP2FN1829AR");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^DeskJet 3700") {
  if (version_is_less(version: fw_ver, test_version: "LYP1FN1828AR")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "LYP1FN1828AR");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^Deskjet Ink Advantage 4510") {
  if (version_is_less(version: fw_ver, test_version: "OAL1CN1828BR")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "OAL1CN1828BR");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^Deskjet Ink Advantage 4530") {
  if (version_is_less(version: fw_ver, test_version: "CCP1FN1827BR")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "CCP1FN1827BR");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^DeskJet Ink Advantage Ultra 4720") {
  if (version_is_less(version: fw_ver, test_version: "SAP1FN1829AR")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "SAP1FN1829AR");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^DeskJet Ink Advantage 5640") {
  if (version_is_less(version: fw_ver, test_version: "NIP1CN1831AR")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "NIP1CN1831AR");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^DeskJet Ink Advantage Ultra 5730") {
  if (version_is_less(version: fw_ver, test_version: "SDP1FN1829AR")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "SDP1FN1829AR");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^DeskJet GT 5820") {
  if (version_is_less(version: fw_ver, test_version: "KWP1FN1829AR")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "KWP1FN1829AR");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^Deskjet 2540") {
  if (version_is_less(version: fw_ver, test_version: "CBP1FN1828BR")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "CBP1FN1828BR");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^DeskJet Ink Advantage 2600") {
  if (version_is_less(version: fw_ver, test_version: "THP1FN1828AR")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "THP1FN1828AR");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^DeskJet Ink Advantage 3700") {
  if (version_is_less(version: fw_ver, test_version: "LAP1FN1828AR")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "LAP1FN1828AR");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^DeskJet Ink Advantage 3830") {
  if (version_is_less(version: fw_ver, test_version: "SUP1FN1830AR")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "SUP1FN1830AR");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^DeskJet Ink Advantage 4640") {
  if (version_is_less(version: fw_ver, test_version: "MZM1FN1830AR")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "MZM1FN1830AR");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^DeskJet Ink Advantage 4670") {
  if (version_is_less(version: fw_ver, test_version: "CEP1FN1830AR")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "CEP1FN1830AR");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^DeskJet Ink Advantage 5570") {
  if (version_is_less(version: fw_ver, test_version: "NCP1CN1831AR")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "NCP1CN1831AR");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^ENVY 120") {
  if (version_is_less(version: fw_ver, test_version: "SCP1CN1827AR")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "SCP1CN1827AR");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^ENVY 4500") {
  if (version_is_less(version: fw_ver, test_version: "MKM1FN1828AR")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "MKM1FN1828AR");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^ENVY 4510") {
  if (version_is_less(version: fw_ver, test_version: "CMP1FN1827BR")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "CMP1FN1827BR");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^ENVY 4520") {
  if (version_is_less(version: fw_ver, test_version: "CFP1FN1827BR")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "CFP1FN1827BR");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^ENVY 5530") {
  if (version_is_less(version: fw_ver, test_version: "ORL1CN1828BR")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "ORL1CN1828BR");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^ENVY 5540") {
  if (version_is_less(version: fw_ver, test_version: "NBP1CN1831AR")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "NBP1CN1831AR");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^ENVY 5640") {
  if (version_is_less(version: fw_ver, test_version: "NLM5CN1830BR")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "NLM5CN1830BR");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^ENVY 5660") {
  if (version_is_less(version: fw_ver, test_version: "NLM5CN1830BR")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "NLM5CN1830BR");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^ENVY 7640") {
  if (version_is_less(version: fw_ver, test_version: "NSM2CN1830AR")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "NSM2CN1830AR");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^Ink Tank Wireless 410") {
  if (version_is_less(version: fw_ver, test_version: "KEP1FN1737JR")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "KEP1FN1737JR");
    security_message(port: 0, data: report);
    exit(0);
  }
  if (fw_ver =~ "KEP1FN1805") {
    if (version_is_less(version: fw_ver, test_version: "KEP1FN1805JR")) {
      report = report_fixed_ver(installed_version: fw_ver, fixed_version: "KEP1FN1805JR");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}

if (model =~ "^OfficeJet 200") {
  if (version_is_less(version: fw_ver, test_version: "RBP1CN1827AR")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "RBP1CN1827AR");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^OfficeJet 250") {
  if (version_is_less(version: fw_ver, test_version: "TZM1CN1828AR")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "TZM1CN1828AR");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^OfficeJet 3830") {
  if (version_is_less(version: fw_ver, test_version: "SPP1FN1830AR")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "SPP1FN1830AR");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^OfficeJet 4620") {
  if (version_is_less(version: fw_ver, test_version: "CWM1FN1829AR")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "CWM1FN1829AR");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^OfficeJet 4630") {
  if (version_is_less(version: fw_ver, test_version: "MYM1FN1830AR")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "MYM1FN1830AR");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^OfficeJet 4650") {
  if (version_is_less(version: fw_ver, test_version: "CUP1FN1830AR")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "CUP1FN1830AR");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^OfficeJet 5740") {
  if (version_is_less(version: fw_ver, test_version: "NPM5CN1830AR")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "NPM5CN1830AR");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^OfficeJet 6600") {
  if (version_is_less(version: fw_ver, test_version: "MIM5CN1827DR")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "MIM5CN1827DR");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^OfficeJet 6700") {
  if (version_is_less(version: fw_ver, test_version: "MPM3CN1827DR")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "MPM3CN1827DR");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^OfficeJet 6950") {
  if (version_is_less(version: fw_ver, test_version: "MJM1CN1828AR")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "MJM1CN1828AR");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^OfficeJet (Pro )?6960") {
  if (version_is_less(version: fw_ver, test_version: "MCP2CN1828AR")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "MCP2CN1828AR");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^OfficeJet 7110") {
  if (version_is_less(version: fw_ver, test_version: "EIP1FN1827AR")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "EIP1FN1827AR");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^OfficeJet 7510") {
  if (version_is_less(version: fw_ver, test_version: "EZM1CN1829AR")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "EZM1CN1829AR");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^OfficeJet 7610") {
  if (version_is_less(version: fw_ver, test_version: "EXM1CN1828BR")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "EXM1CN1828BR");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^Officejet Pro 251dw") {
  if (version_is_less(version: fw_ver, test_version: "EVP1CN1828AR")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "EVP1CN1828AR");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^Officejet Pro 276dw") {
  if (version_is_less(version: fw_ver, test_version: "FRP1CN1829AR")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "FRP1CN1829AR");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^Officejet Pro 3610") {
  if (version_is_less(version: fw_ver, test_version: "MSP1CN1828AR")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "MSP1CN1828AR");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^Officejet Pro 6830") {
  if (version_is_less(version: fw_ver, test_version: "PNP1CN1828AR")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "PNP1CN1828AR");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^Officejet Pro 6970") {
  if (version_is_less(version: fw_ver, test_version: "MCP2CN1828AR")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "MCP2CN1828AR");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^Officejet Pro 7740") {
  if (version_is_less(version: fw_ver, test_version: "EDWINXPP1N002.1828A.00")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "EDWINXPP1N002.1828A.00");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^Officejet Pro 8210") {
  if (version_is_less(version: fw_ver, test_version: "TESPDLPP1N001.1827B.00")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "TESPDLPP1N001.1827B.00");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^Officejet Pro 8600") {
  # e.g. CKP1CN1545AR
  if (fw_ver =~"^CKP1CN" ) {
    if (version_is_less(version: fw_ver, test_version: "CKP1CN1829AR")) {
      report = report_fixed_ver(installed_version: fw_ver, fixed_version: "CKP1CN1829AR");
      security_message(port: 0, data: report);
      exit(0);
    }
  } else {
    if (version_is_less(version: fw_ver, test_version: "CLP1CN1829AR")) {
      report = report_fixed_ver(installed_version: fw_ver, fixed_version: "CLP1CN1829AR");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}

if (model =~ "^Officejet Pro 8610") {
  if (version_is_less(version: fw_ver, test_version: "FDP1CN1828AR")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "FDP1CN1828AR");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^Officejet Pro 8620") {
  if (version_is_less(version: fw_ver, test_version: "FDP1CN1828AR")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "FDP1CN1828AR");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^Officejet Pro 8630") {
  if (version_is_less(version: fw_ver, test_version: "FDP1CN1828AR")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "FDP1CN1828AR");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^Officejet Pro 8640") {
  if (version_is_less(version: fw_ver, test_version: "FDP1CN1828BR")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "FDP1CN1828BR");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^Officejet Pro 8660") {
  if (version_is_less(version: fw_ver, test_version: "FDP1CN1828AR")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "FDP1CN1828AR");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^Officejet Pro 8710") {
  if (version_is_less(version: fw_ver, test_version: "WBP2CN1828AR")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "WBP2CN1828AR");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^Officejet Pro 8720") {
  if (version_is_less(version: fw_ver, test_version: "WMP1CN1828AR")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "WMP1CN1828AR");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^Officejet Pro 8730") {
  if (version_is_less(version: fw_ver, test_version: "WEBPDLPP1N001.1827B.00")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "WEBPDLPP1N001.1827B.00");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^Officejet Pro 8740") {
  if (version_is_less(version: fw_ver, test_version: "WEBPDLPP1N001.1827B.00")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "WEBPDLPP1N001.1827B.00");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^Photosmart 5510") {
  if (version_is_less(version: fw_ver, test_version: "EPL2CN1832AR")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "EPL2CN1832AR");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^Photosmart 5510d") {
  if (version_is_less(version: fw_ver, test_version: "EDL1CN1829BR")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "EDL1CN1829BR");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^Photosmart 5520") {
  if (version_is_less(version: fw_ver, test_version: "MGP5CN1828BR")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "MGP5CN1828BR");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^Photosmart 6510") {
  if (version_is_less(version: fw_ver, test_version: "ESP1CN1829BR")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "ESP1CN1829BR");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^Photosmart 6520") {
  if (version_is_less(version: fw_ver, test_version: "PKM2CN1828BR")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "PKM2CN1828BR");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^Photosmart 7520") {
  if (version_is_less(version: fw_ver, test_version: "ELM1CN1830AR")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "ELM1CN1830AR");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^Photosmart Plus B210") {
  if (version_is_less(version: fw_ver, test_version: "TAL1FN1829AR")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "TAL1FN1829AR");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^Smart Tank Wireless 450") {
  if (version_is_less(version: fw_ver, test_version: "KDP1FN1737JR")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "KDP1FN1737JR");
    security_message(port: 0, data: report);
    exit(0);
  }
  if (fw_ver =~ "KDP1FN1805") {
    if (version_is_less(version: fw_ver, test_version: "KDP1FN1805JR")) {
      report = report_fixed_ver(installed_version: fw_ver, fixed_version: "KEP1FN1805JR");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}

exit(99);
