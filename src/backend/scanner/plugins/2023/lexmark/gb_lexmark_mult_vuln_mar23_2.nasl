# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

CPE_PREFIX = "cpe:/o:lexmark:";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.170367");
  script_version("2023-03-24T10:09:03+0000");
  script_tag(name:"last_modification", value:"2023-03-24 10:09:03 +0000 (Fri, 24 Mar 2023)");
  script_tag(name:"creation_date", value:"2023-03-16 21:10:29 +0000 (Thu, 16 Mar 2023)");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2023-26067", "CVE-2023-26068");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Lexmark Printer Multiple Input Validation Vulnerabilities (Mar 2023)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_lexmark_printer_consolidation.nasl");
  script_mandatory_keys("lexmark_printer/detected");

  script_tag(name:"summary", value:"Multiple Lexmark printer devices are prone to multiple input validation
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable firmware version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist in the Postscript interpreter:

  - CVE-2023-26067: Tnput validation vulnerability that allows an attacker who has already compromised an
  affected Lexmark device to escalate privileges.

  - CVE-2023-26068: The embedded web server in newer Lexmark devices fails to properly sanitize input data.");

  script_tag(name:"impact", value:"These vulnerabilities can be leveraged by an attacker to execute
  arbitrary code.");

  script_tag(name:"solution", value:"See the referenced vendor advisories for a solution.");

  script_xref(name:"URL", value:"https://publications.lexmark.com/publications/security-alerts/CVE-2023-26067.pdf");
  script_xref(name:"URL", value:"https://publications.lexmark.com/publications/security-alerts/CVE-2023-26068.pdf");

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

if (cpe =~ "^cpe:/o:lexmark:cx93[01]" || cpe =~ "^cpe:/o:lexmark:cx94[234]" ||
    cpe =~ "^cpe:/o:lexmark:xc9335" || cpe =~ "^cpe:/o:lexmark:xc94[456]5") {
  if (version_is_less_equal(version: version, test_version: "CXTPC.081.232")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CXTPC.081.233");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:cs943") {
  if (version_is_less_equal(version: version, test_version: "CSTPC.081.232")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CSTPC.081.233");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:mx432" || cpe =~ "^cpe:/o:lexmark:xm3142") {
  if (version_is_less_equal(version: version, test_version: "MXTCT.081.232")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "MXTCT.081.233");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:mx931") {
  if (version_is_less_equal(version: version, test_version: "MXTPM.081.232")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "MXTPM.081.233");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:cx73[05]" || cpe =~ "^cpe:/o:lexmark:xc43[45]2") {
  if (version_is_less_equal(version: version, test_version: "CXTMM.081.232")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CXTMM.081.233");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:cs73[05]" || cpe =~ "^cpe:/o:lexmark:c43[45]2") {
  if (version_is_less_equal(version: version, test_version: "CSTMM.081.232")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CSTMM.081.233");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:b2236") {
  if (version_is_less_equal(version: version, test_version: "MSLSG.081.232")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "MSLSG.081.233");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:mb2236") {
  if (version_is_less_equal(version: version, test_version: "MXLSG.081.232")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "MXLSG.081.233");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:ms[34]31" || cpe =~ "^cpe:/o:lexmark:m1342" ||
    cpe =~ "^cpe:/o:lexmark:b3442" || cpe =~ "^cpe:/o:lexmark:b3340"||
    cpe =~ "^cpe:/o:lexmark:xm1342") {
  if (version_is_less_equal(version: version, test_version: "MSLBD.081.232")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "MSLBD.081.233");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:mx[34]31" || cpe =~ "^cpe:/o:lexmark:mb3442") {
  if (version_is_less_equal(version: version, test_version: "MXLBD.081.232")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "MXLBD.081.233");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:ms[3456]21" || cpe =~ "^cpe:/o:lexmark:m124[26]" ||
    cpe =~ "^cpe:/o:lexmark:b2338" || cpe =~ "^cpe:/o:lexmark:b2442" ||
    cpe =~ "^cpe:/o:lexmark:b2546" || cpe =~ "^cpe:/o:lexmark:b2650") {
  if (version_is_less_equal(version: version, test_version: "MSNGM.081.232")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "MSNGM.081.233");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:ms622" || cpe =~ "^cpe:/o:lexmark:m3250") {
  if (version_is_less_equal(version: version, test_version: "MSTGM.081.232")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "MSTGM.081.233");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:mx321" || cpe =~ "^cpe:/o:lexmark:mb2338") {
  if (version_is_less_equal(version: version, test_version: "MXNGM.081.232")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "MXNGM.081.233");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:mx[45]21" || cpe =~ "^cpe:/o:lexmark:mx[56]22" ||
    cpe =~ "^cpe:/o:lexmark:xm124[26]" || cpe =~ "^cpe:/o:lexmark:xm3250" ||
    cpe =~ "^cpe:/o:lexmark:mb2442" || cpe =~ "^cpe:/o:lexmark:mb2546" ||
    cpe =~ "^cpe:/o:lexmark:mb2650") {
  if (version_is_less_equal(version: version, test_version: "MXTGM.081.232")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "MXTGM.081.233");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:ms[78]25" || cpe =~ "^cpe:/o:lexmark:ms82[13]" ||
    cpe =~ "^cpe:/o:lexmark:b2865") {
  if (version_is_less_equal(version: version, test_version: "MSNGW.081.232")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "MSNGW.081.233");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:ms82[26]" || cpe =~ "^cpe:/o:lexmark:m5255" ||
    cpe =~ "^cpe:/o:lexmark:m5270") {
  if (version_is_less_equal(version: version, test_version: "MSTGW.081.232")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "MSTGW.081.233");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:mx72[12]" || cpe =~ "^cpe:/o:lexmark:mx82[26]" ||
    cpe =~ "^cpe:/o:lexmark:xm5365" || cpe =~ "^cpe:/o:lexmark:xm73(55|70)" ||
    cpe =~ "^cpe:/o:lexmark:mb2770") {
  if (version_is_less_equal(version: version, test_version: "MXTGW.081.232")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "MXTGW.081.233");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:c3426" || cpe =~ "^cpe:/o:lexmark:cs43[19]") {
  if (version_is_less_equal(version: version, test_version: "CSLBN.081.232")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CSLBN.081.233");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:cs331" || cpe =~ "^cpe:/o:lexmark:c3224" ||
    cpe =~ "^cpe:/o:lexmark:c3326") {
  if (version_is_less_equal(version: version, test_version: "CSLBL.081.232")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CSLBL.081.233");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:c2326") {
  if (version_is_less_equal(version: version, test_version: "CSLBN.081.232")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CSLBN.081.233");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:mc3426" || cpe =~ "^cpe:/o:lexmark:cx431" ||
    cpe =~ "^cpe:/o:lexmark:xc2326") {
  if (version_is_less_equal(version: version, test_version: "CXLBN.081.232")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CXLBN.081.233");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:mc3224" || cpe =~ "^cpe:/o:lexmark:mc3326" ||
    cpe =~ "^cpe:/o:lexmark:cx331") {
  if (version_is_less_equal(version: version, test_version: "CXLBL.081.232")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CXLBL.081.233");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:cs622" || cpe =~ "^cpe:/o:lexmark:c2240") {
  if (version_is_less_equal(version: version, test_version: "CSTZJ.081.232")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CSTZJ.081.233");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:cs[45]21" || cpe =~ "^cpe:/o:lexmark:c2[34]25" ||
    cpe =~ "^cpe:/o:lexmark:c2535") {
  if (version_is_less_equal(version: version, test_version: "CSNZJ.081.232")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CSNZJ.081.233");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:cx[56]22" || cpe =~ "^cpe:/o:lexmark:cx625" ||
    cpe =~ "^cpe:/o:lexmark:xc2235" || cpe =~ "^cpe:/o:lexmark:xc4240" ||
    cpe =~ "^cpe:/o:lexmark:mc2535" || cpe =~ "^cpe:/o:lexmark:mc2640") {
  if (version_is_less_equal(version: version, test_version: "CXTZJ.081.232")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CXTZJ.081.233");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:cx421" || cpe =~ "^cpe:/o:lexmark:mc2[34]25") {
  if (version_is_less_equal(version: version, test_version: "CXNZJ.081.232")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CXNZJ.081.233");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:cx82[057]" || cpe =~ "^cpe:/o:lexmark:cx860" ||
    cpe =~ "^cpe:/o:lexmark:xc615[23]" || cpe =~ "^cpe:/o:lexmark:xc81(55|60|63)") {
  if (version_is_less_equal(version: version, test_version: "CXTPP.081.232")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CXTPP.081.233");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:cs82[07]" || cpe =~ "^cpe:/o:lexmark:c6160") {
  if (version_is_less_equal(version: version, test_version: "CSTPP.081.232")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CSTPP.081.233");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:cs72[0578]" || cpe =~ "^cpe:/o:lexmark:c4150") {
  if (version_is_less_equal(version: version, test_version: "CSTAT.081.232")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CSTAT.081.233");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:cx72[57]" || cpe =~ "^cpe:/o:lexmark:xc41(40|43|50|53)") {
  if (version_is_less_equal(version: version, test_version: "CXTAT.081.232")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CXTAT.081.233");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:cs92[137]" || cpe =~ "^cpe:/o:lexmark:c9235") {
  if (version_is_less_equal(version: version, test_version: "CSTMH.081.232")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CSTMH.081.233");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:cx92[01234]" || cpe =~ "^cpe:/o:lexmark:xc92[23456]5") {
  if (version_is_less_equal(version: version, test_version: "CXTMH.081.232")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CXTMH.081.233");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);
