# Copyright (C) 2022 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
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

CPE_PREFIX = "cpe:/o:lexmark:";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.147501");
  script_version("2022-01-25T05:03:13+0000");
  script_tag(name:"last_modification", value:"2022-01-25 11:07:10 +0000 (Tue, 25 Jan 2022)");
  script_tag(name:"creation_date", value:"2022-01-24 08:38:57 +0000 (Mon, 24 Jan 2022)");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:M/C:C/I:C/A:C");

  script_cve_id("CVE-2021-44734", "CVE-2021-44737", "CVE-2021-44738");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Lexmark Printer Multiple Vulnerabilities (Jan 2022)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_lexmark_printer_consolidation.nasl");
  script_mandatory_keys("lexmark_printer/detected");

  script_tag(name:"summary", value:"Multiple Lexmark printer devices are prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable firmware version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2021-44734: Remote code execution (RCE)

  - CVE-2021-44737: PJL directory traversal

  - CVE-2021-44738: Buffer overflow in postscript interpreter");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_xref(name:"URL", value:"https://publications.lexmark.com/publications/security-alerts/CVE-2021-44734.pdf");
  script_xref(name:"URL", value:"https://publications.lexmark.com/publications/security-alerts/CVE-2021-44737.pdf");
  script_xref(name:"URL", value:"https://publications.lexmark.com/publications/security-alerts/CVE-2021-44738.pdf");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!infos = get_app_port_from_cpe_prefix(cpe: CPE_PREFIX, first_cpe_only: TRUE))
  exit(0);

port = infos["port"];
cpe = infos["cpe"];

if (!version = toupper(get_app_version(cpe: cpe, port: port, nofork: TRUE)))
  exit(0);

if (cpe =~ "^cpe:/o:lexmark:b2236") {
  if (version_is_less_equal(version: version, test_version: "MSLSG.076.293")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "MSLSG.076.294");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:mb2236") {
  if (version_is_less_equal(version: version, test_version: "MXLSG.076.293")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "MXLSG.076.294");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:ms[34]31" || cpe =~ "^cpe:/o:lexmark:m1342" ||
    cpe =~ "^cpe:/o:lexmark:b3442" || cpe =~ "^cpe:/o:lexmark:b3340" ||
    cpe =~ "^cpe:/o:lexmark:xm1342") {
  if (version_is_less_equal(version: version, test_version: "MSLBD.076.293")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "MSLBD.076.294");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:mx[34]31" || cpe =~ "^cpe:/o:lexmark:mb3442") {
  if (version_is_less_equal(version: version, test_version: "MXLBD.076.293")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "MXLBD.076.294");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:ms[3456]21" || cpe =~ "^cpe:/o:lexmark:m124[26]" ||
    cpe =~ "^cpe:/o:lexmark:b2338" || cpe =~ "^cpe:/o:lexmark:b2442" ||
    cpe =~ "^cpe:/o:lexmark:b2546" || cpe =~ "^cpe:/o:lexmark:b2650") {
  if (version_is_less_equal(version: version, test_version: "MSNGM.076.293")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "MSNGM.076.294");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:ms622" || cpe =~ "^cpe:/o:lexmark:m3250") {
  if (version_is_less_equal(version: version, test_version: "MSTGM.076.293")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "MSTGM.076.294");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:mx321" || cpe =~ "^cpe:/o:lexmark:mb2338") {
  if (version_is_less_equal(version: version, test_version: "MXNGM.076.293")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "MXNGM.076.294");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:mx[45]21" || cpe =~ "^cpe:/o:lexmark:mx[56]22" ||
    cpe =~ "^cpe:/o:lexmark:xm124[26]" || cpe =~ "^cpe:/o:lexmark:xm3250" ||
    cpe =~ "^cpe:/o:lexmark:mb2442" || cpe =~ "^cpe:/o:lexmark:mb2546" ||
    cpe =~ "^cpe:/o:lexmark:mb2650") {
  if (version_is_less_equal(version: version, test_version: "MXTGM.076.293")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "MXTGM.076.294");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:ms725" || cpe =~ "^cpe:/o:lexmark:ms82[135]" ||
    cpe =~ "^cpe:/o:lexmark:b2865") {
  if (version_is_less_equal(version: version, test_version: "MSNGW.076.293")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "MSNGW.076.294");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:ms82[26]" || cpe =~ "^cpe:/o:lexmark:m5255" ||
    cpe =~ "^cpe:/o:lexmark:m5270") {
  if (version_is_less_equal(version: version, test_version: "MSTGW.076.293")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "MSTGW.076.294");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:mx72[12]" || cpe =~ "^cpe:/o:lexmark:mx82[26]" ||
    cpe =~ "^cpe:/o:lexmark:xm5365" || cpe =~ "^cpe:/o:lexmark:xm7355" ||
    cpe =~ "^cpe:/o:lexmark:xm7370" || cpe =~ "^cpe:/o:lexmark:mb2770") {
  if (version_is_less_equal(version: version, test_version: "MXTGW.076.293")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "MXTGW.076.294");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:c3426" || cpe =~ "^cpe:/o:lexmark:cs43[19]") {
  if (version_is_less_equal(version: version, test_version: "CSLBN.076.293")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CSLBN.076.294");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:cs331" || cpe =~ "^cpe:/o:lexmark:c3224" ||
    cpe =~ "^cpe:/o:lexmark:c3326") {
  if (version_is_less_equal(version: version, test_version: "CSLBL.076.293")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CSLBL.076.294");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:c2326") {
  if (version_is_less_equal(version: version, test_version: "CSLBN.076.293")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CSLBN.076.294");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:mc3426" || cpe =~ "^cpe:/o:lexmark:cx431" ||
    cpe =~ "^cpe:/o:lexmark:xc2326") {
  if (version_is_less_equal(version: version, test_version: "CXLBN.076.293")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CXLBN.076.294");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:mc3224" || cpe =~ "^cpe:/o:lexmark:mc3326" ||
    cpe =~ "^cpe:/o:lexmark:cx331") {
  if (version_is_less_equal(version: version, test_version: "CXLBL.076.293")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CXLBL.076.294");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:cs622" || cpe =~ "^cpe:/o:lexmark:c2240") {
  if (version_is_less_equal(version: version, test_version: "CSTZJ.076.293")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CSTZJ.076.294");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:cs[45]21" || cpe =~ "^cpe:/o:lexmark:c2[34]25" ||
    cpe =~ "^cpe:/o:lexmark:c2535") {
  if (version_is_less_equal(version: version, test_version: "CSNZJ.076.293")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CSNZJ.076.294");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:cx[56]22" || cpe =~ "^cpe:/o:lexmark:cx625" ||
    cpe =~ "^cpe:/o:lexmark:xc2235" || cpe =~ "^cpe:/o:lexmark:xc4240" ||
    cpe =~ "^cpe:/o:lexmark:mc2535" || cpe =~ "^cpe:/o:lexmark:mc2640") {
  if (version_is_less_equal(version: version, test_version: "CXTZJ.076.293")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CXTZJ.076.294");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:cx421" || cpe =~ "^cpe:/o:lexmark:mc2[34]25") {
  if (version_is_less_equal(version: version, test_version: "CXNZJ.076.293")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CXNZJ.076.294");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:cx82[057]" || cpe =~ "^cpe:/o:lexmark:cx860" ||
    cpe =~ "^cpe:/o:lexmark:xc615[23]" || cpe =~ "^cpe:/o:lexmark:xc8155" ||
    cpe =~ "^cpe:/o:lexmark:xc816[03]") {
  if (version_is_less_equal(version: version, test_version: "CXTPP.076.293")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CXTPP.076.294");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:cs82[07]" || cpe =~ "^cpe:/o:lexmark:c6160") {
  if (version_is_less_equal(version: version, test_version: "CSTPP.076.293")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CSTPP.076.294");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:cs72[0578]" || cpe =~ "^cpe:/o:lexmark:c4150") {
  if (version_is_less_equal(version: version, test_version: "CSTAT.076.293")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CSTAT.076.294");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:cx72[57]" || cpe =~ "^cpe:/o:lexmark:xc414[03]" ||
    cpe =~ "^cpe:/o:lexmark:xc415[03]") {
  if (version_is_less_equal(version: version, test_version: "CXTAT.076.293")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CXTAT.076.294");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:cs92[137]" || cpe =~ "^cpe:/o:lexmark:c9235") {
  if (version_is_less_equal(version: version, test_version: "CSTMH.076.293")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CSTMH.076.294");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:cx92[01234]" || cpe =~ "^cpe:/o:lexmark:xc92[23456]5") {
  if (version_is_less_equal(version: version, test_version: "CXTMH.076.293")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CXTMH.076.294");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:ms31[027]" || cpe =~ "^cpe:/o:lexmark:ms410" ||
    cpe =~ "^cpe:/o:lexmark:m1140") {
  if (version_is_less_equal(version: version, test_version: "LW80.PRL.P209")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "LW80.PRL.P210");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:ms[34]15" || cpe =~ "^cpe:/o:lexmark:ms417") {
  if (version_is_less_equal(version: version, test_version: "LW80.TL2.P209")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "LW80.TL2.P210");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:ms51[07]" || cpe =~ "^cpe:/o:lexmark:ms610dn" ||
    cpe =~ "^cpe:/o:lexmark:ms617" || cpe =~ "^cpe:/o:lexmark:m1140" ||
    cpe =~ "^cpe:/o:lexmark:m1145" || cpe =~ "^cpe:/o:lexmark:m3150dn") {
  if (version_is_less_equal(version: version, test_version: "LW80.PR2.P209")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "LW80.PR2.P210");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:ms610de" || cpe =~ "^cpe:/o:lexmark:m3150de") {
  if (version_is_less_equal(version: version, test_version: "LW80.PR4.P209")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "LW80.PR4.P210");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:mx31[07]" || cpe =~ "^cpe:/o:lexmark:xm1135") {
  if (version_is_less_equal(version: version, test_version: "LW80.SB2.P209")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "LW80.SB2.P210");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:mx41[07]" || cpe =~ "^cpe:/o:lexmark:mx51[017]" ||
    cpe =~ "^cpe:/o:lexmark:xm114[05]") {
  if (version_is_less_equal(version: version, test_version: "LW80.SB4.P209")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "LW80.SB4.P210");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:mx61[017]" || cpe =~ "^cpe:/o:lexmark:xm3150") {
  if (version_is_less_equal(version: version, test_version: "LW80.SB7.P209")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "LW80.SB7.P210");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:ms71[01]" || cpe =~ "^cpe:/o:lexmark:ms81[02]dn" ||
    cpe =~ "^cpe:/o:lexmark:ms81[178]" || cpe =~ "^cpe:/o:lexmark:m5163dn") {
  if (version_is_less_equal(version: version, test_version: "LW80.DN2.P209")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "LW80.DN2.P210");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:ms810de" || cpe =~ "^cpe:/o:lexmark:m5155" ||
    cpe =~ "^cpe:/o:lexmark:m5163de") {
  if (version_is_less_equal(version: version, test_version: "LW80.DN4.P209")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "LW80.DN4.P210");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:ms812de" || cpe =~ "^cpe:/o:lexmark:m5170") {
  if (version_is_less_equal(version: version, test_version: "LW80.DN7.P209")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "LW80.DN7.P210");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:mx71[0178]" || cpe =~ "^cpe:/o:lexmark:mx81[012]" ||
    cpe =~ "^cpe:/o:lexmark:xm[57]163" || cpe =~ "^cpe:/o:lexmark:xm[57][12]70" ||
    cpe =~ "^cpe:/o:lexmark:xm[57]263" || cpe =~ "^cpe:/o:lexmark:xm7155") {
  if (version_is_less_equal(version: version, test_version: "LW80.TU.P209")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "LW80.TU.P210");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:ms911") {
  if (version_is_less_equal(version: version, test_version: "LW80.SA.P209")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "LW80.SA.P210");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:mx91[012]" || cpe =~ "^cpe:/o:lexmark:xm91[456]5") {
  if (version_is_less_equal(version: version, test_version: "LW80.MG.P209")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "LW80.MG.P210");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:mx6500e") {
  if (version_is_less_equal(version: version, test_version: "LW80.JD.P209")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "LW80.JD.P210");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:cs31[07]") {
  if (version_is_less_equal(version: version, test_version: "LW80.VYL.P209")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "LW80.VYL.P210");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:cs41[07]") {
  if (version_is_less_equal(version: version, test_version: "LW80.VY2.P209")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "LW80.VY2.P210");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:cs51[07]" || cpe =~ "^cpe:/o:lexmark:c2132") {
  if (version_is_less_equal(version: version, test_version: "LW80.VY4.P209")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "LW80.VY4.P210");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:cx31[07]") {
  if (version_is_less_equal(version: version, test_version: "LW80.GM2.P209")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "LW80.GM2.P210");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:cx41[07]" || cpe =~ "^cpe:/o:lexmark:xc2130") {
  if (version_is_less_equal(version: version, test_version: "LW80.GM4.P209")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "LW80.GM4.P210");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:cx51[07]" || cpe =~ "^cpe:/o:lexmark:xc2132") {
  if (version_is_less_equal(version: version, test_version: "LW80.GM7.P209")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "LW80.GM7.P210");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:c746") {
  if (version_is_less_equal(version: version, test_version: "LHS60.CM2.P752")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "LHS60.CM2.P753");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:cs?748") {
  if (version_is_less_equal(version: version, test_version: "LHS60.CM4.P752")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "LHS60.CM4.P753");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:c792" || cpe =~ "^cpe:/o:lexmark:cs796") {
  if (version_is_less_equal(version: version, test_version: "LHS60.HC.P752")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "LHS60.HC.P753");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:c925") {
  if (version_is_less_equal(version: version, test_version: "LHS60.HV.P752")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "LHS60.HV.P753");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:c950") {
  if (version_is_less_equal(version: version, test_version: "LHS60.TP.P752")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "LHS60.TP.P753");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:xs?548") {
  if (version_is_less_equal(version: version, test_version: "LHS60.VK.P752")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "LHS60.VK.P753");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:x746" || cpe =~ "^cpe:/o:lexmark:xs?748") {
  if (version_is_less_equal(version: version, test_version: "LHS60.NY.P752")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "LHS60.NY.P753");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:x792" || cpe =~ "^cpe:/o:lexmark:xs79[568]") {
  if (version_is_less_equal(version: version, test_version: "LHS60.MR.P752")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "LHS60.MR.P753");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:xs?925") {
  if (version_is_less_equal(version: version, test_version: "LHS60.HK.P752")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "LHS60.HK.P753");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:x95[024]" || cpe =~ "^cpe:/o:lexmark:xs95[05]") {
  if (version_is_less_equal(version: version, test_version: "LHS60.TQ.P752")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "LHS60.TQ.P753");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:6500e") {
  if (version_is_less_equal(version: version, test_version: "LHS60.JR.P752")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "LHS60.JR.P753");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:c734") {
  if (version_is_less_equal(version: version, test_version: "LR.SK.P834")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "LR.SK.P835");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:c736") {
  if (version_is_less_equal(version: version, test_version: "LR.SKE.P834")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "LR.SKE.P835");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:e46") {
  if (version_is_less_equal(version: version, test_version: "LR.LBH.P834")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "LR.LBH.P835");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:t65") {
  if (version_is_less_equal(version: version, test_version: "LR.JP.P834")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "LR.JP.P835");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:x46") {
  if (version_is_less_equal(version: version, test_version: "LR.BS.P834")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "LR.BS.P835");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:x65") {
  if (version_is_less_equal(version: version, test_version: "LR.MN.P834")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "LR.MN.P835");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:x73") {
  if (version_is_less_equal(version: version, test_version: "LR.FL.P834")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "LR.FL.P835");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:w850") {
  if (version_is_less_equal(version: version, test_version: "LP.JB.P833")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "LP.JB.P834");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:x86") {
  if (version_is_less_equal(version: version, test_version: "LP.SP.P833")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "LP.SP.P834");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);
