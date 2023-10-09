# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.170554");
  script_version("2023-08-25T16:09:51+0000");
  script_tag(name:"last_modification", value:"2023-08-25 16:09:51 +0000 (Fri, 25 Aug 2023)");
  script_tag(name:"creation_date", value:"2023-08-24 16:46:09 +0000 (Thu, 24 Aug 2023)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_cve_id("CVE-2023-29984");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Brother Printers DoS Vulnerability (Jul 2023)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_brother_printer_consolidation.nasl");
  script_mandatory_keys("brother/printer/detected");

  script_tag(name:"summary", value:"Multiple Brother printers are prone to a denial of service (DoS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable firmware version is present on the target host.");

  script_tag(name:"insight", value:"The printer restarts when you are configuring settings on the Web
  Based Management page of the Embedded Web Server.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_xref(name:"URL", value:"https://support.brother.com/g/b/faqend.aspx?c=us&lang=en&prod=group2&faqid=faq00100793_000");
  script_xref(name:"URL", value:"https://support.brother.com/g/s/id/security/CVE-2023-29984_modellist.pdf");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

cpe_list = make_list("cpe:/o:brother:dcp-1610w_firmware",
                     "cpe:/o:brother:dcp-1610we_firmware",
                     "cpe:/o:brother:dcp-1610wr_firmware",
                     "cpe:/o:brother:dcp-1610wvb_firmware",
                     "cpe:/o:brother:dcp-1612w_firmware",
                     "cpe:/o:brother:dcp-1612we_firmware",
                     "cpe:/o:brother:dcp-1612wr_firmware",
                     "cpe:/o:brother:dcp-1612wvb_firmware",
                     "cpe:/o:brother:dcp-1615nw_firmware",
                     "cpe:/o:brother:dcp-1616nw_firmware",
                     "cpe:/o:brother:dcp-1617nw_firmware",
                     "cpe:/o:brother:dcp-1618w_firmware",
                     "cpe:/o:brother:dcp-1622we_firmware",
                     "cpe:/o:brother:dcp-1623we_firmware",
                     "cpe:/o:brother:dcp-1623wr_firmware",
                     "cpe:/o:brother:dcp-7180dn_firmware",
                     "cpe:/o:brother:dcp-j4120dw_firmware",
                     "cpe:/o:brother:dcp-j4220n-b_firmware",
                     "cpe:/o:brother:dcp-j4220n-w_firmware",
                     "cpe:/o:brother:dcp-j4225n-b_firmware",
                     "cpe:/o:brother:dcp-j4225n-w_firmware",
                     "cpe:/o:brother:dcp-j562dw_firmware",
                     "cpe:/o:brother:dcp-j562n_firmware",
                     "cpe:/o:brother:dcp-j567n_firmware",
                     "cpe:/o:brother:dcp-j572dw_firmware",
                     "cpe:/o:brother:dcp-j572n_firmware",
                     "cpe:/o:brother:dcp-j577n_firmware",
                     "cpe:/o:brother:dcp-j582n_firmware",
                     "cpe:/o:brother:dcp-j587n_firmware",
                     "cpe:/o:brother:dcp-j762n_firmware",
                     "cpe:/o:brother:dcp-j767n_firmware",
                     "cpe:/o:brother:dcp-j772dw_firmware",
                     "cpe:/o:brother:dcp-j774dw_firmware",
                     "cpe:/o:brother:dcp-j785dw_firmware",
                     "cpe:/o:brother:dcp-j962n_firmware",
                     "cpe:/o:brother:dcp-j963n-w_firmware",
                     "cpe:/o:brother:dcp-j963n-b_firmware",
                     "cpe:/o:brother:dcp-j968n-w_firmware",
                     "cpe:/o:brother:dcp-j968n-b_firmware",
                     "cpe:/o:brother:dcp-j972n_firmware",
                     "cpe:/o:brother:dcp-j973n-b_firmware",
                     "cpe:/o:brother:dcp-j973n-w_firmware",
                     "cpe:/o:brother:dcp-j978n-b_firmware",
                     "cpe:/o:brother:dcp-j978n-w_firmware",
                     "cpe:/o:brother:dcp-j981n_firmware",
                     "cpe:/o:brother:dcp-j982n-b_firmware",
                     "cpe:/o:brother:dcp-j982n-w_firmware",
                     "cpe:/o:brother:dcp-j983n_firmware",
                     "cpe:/o:brother:dcp-j987n-b_firmware",
                     "cpe:/o:brother:dcp-j987n-w_firmware",
                     "cpe:/o:brother:dcp-l2520dw_firmware",
                     "cpe:/o:brother:dcp-l2520dwr_firmware",
                     "cpe:/o:brother:dcp-l2540dn_firmware",
                     "cpe:/o:brother:dcp-l2540dnr_firmware",
                     "cpe:/o:brother:dcp-l2540dw_firmware",
                     "cpe:/o:brother:dcp-l2541dw_firmware",
                     "cpe:/o:brother:dcp-l2560dw_firmware",
                     "cpe:/o:brother:dcp-l2560dwr_firmware",
                     "cpe:/o:brother:dcp-l8410cdw_firmware",
                     "cpe:/o:brother:dcp-t510w_firmware",
                     "cpe:/o:brother:dcp-t710w_firmware",
                     "cpe:/o:brother:fax-l2700dn_firmware",
                     "cpe:/o:brother:hl-1210w_firmware",
                     "cpe:/o:brother:hl-1210we_firmware",
                     "cpe:/o:brother:hl-1210wr_firmware",
                     "cpe:/o:brother:hl-1210wvb_firmware",
                     "cpe:/o:brother:hl-1211w_firmware",
                     "cpe:/o:brother:hl-1212w_firmware",
                     "cpe:/o:brother:hl-1212we_firmware",
                     "cpe:/o:brother:hl-1212wr_firmware",
                     "cpe:/o:brother:hl-1212wvb_firmware",
                     "cpe:/o:brother:hl-1218w_firmware",
                     "cpe:/o:brother:hl-1222we_firmware",
                     "cpe:/o:brother:hl-1223we_firmware",
                     "cpe:/o:brother:hl-1223wr_firmware",
                     "cpe:/o:brother:hl-2560dn_firmware",
                     "cpe:/o:brother:hl-l2305w_firmware",
                     "cpe:/o:brother:hl-l2315dw_firmware",
                     "cpe:/o:brother:hl-l2340dw_firmware",
                     "cpe:/o:brother:hl-l2340dwr_firmware",
                     "cpe:/o:brother:hl-l2360dn_firmware",
                     "cpe:/o:brother:hl-l2360dnr_firmware",
                     "cpe:/o:brother:hl-l2360dw_firmware",
                     "cpe:/o:brother:hl-l2361dn_firmware",
                     "cpe:/o:brother:hl-l2365dw_firmware",
                     "cpe:/o:brother:hl-l2365dwr_firmware",
                     "cpe:/o:brother:hl-l2366dw_firmware",
                     "cpe:/o:brother:hl-l2380dw_firmware",
                     "cpe:/o:brother:hl-l8260cdn_firmware",
                     "cpe:/o:brother:hl-l8260cdw_firmware",
                     "cpe:/o:brother:hl-l8360cdw_firmware",
                     "cpe:/o:brother:hl-l8360cdwt_firmware",
                     "cpe:/o:brother:hl-l9310cdw_firmware",
                     "cpe:/o:brother:mfc-1910w_firmware",
                     "cpe:/o:brother:mfc-1910we_firmware",
                     "cpe:/o:brother:mfc-1911nw_firmware",
                     "cpe:/o:brother:mfc-1911w_firmware",
                     "cpe:/o:brother:mfc-1912wr_firmware",
                     "cpe:/o:brother:mfc-1915w_firmware",
                     "cpe:/o:brother:mfc-1916nw_firmware",
                     "cpe:/o:brother:mfc-1919nw_firmware",
                     "cpe:/o:brother:mfc-7880dn_firmware",
                     "cpe:/o:brother:mfc-j2320_firmware",
                     "cpe:/o:brother:mfc-j2330dw_firmware",
                     "cpe:/o:brother:mfc-j2720_firmware",
                     "cpe:/o:brother:mfc-j2730dw_firmware",
                     "cpe:/o:brother:mfc-j3530dw_firmware",
                     "cpe:/o:brother:mfc-j3930dw_firmware",
                     "cpe:/o:brother:mfc-j4320dw_firmware",
                     "cpe:/o:brother:mfc-j4420dw_firmware",
                     "cpe:/o:brother:mfc-j460dw_firmware",
                     "cpe:/o:brother:mfc-j4620dw_firmware",
                     "cpe:/o:brother:mfc-j4625dw_firmware",
                     "cpe:/o:brother:mfc-j4720n_firmware",
                     "cpe:/o:brother:mfc-j4725n_firmware",
                     "cpe:/o:brother:mfc-j480dw_firmware",
                     "cpe:/o:brother:mfc-j485dw_firmware",
                     "cpe:/o:brother:mfc-j491dw_firmware",
                     "cpe:/o:brother:mfc-j497dw_firmware",
                     "cpe:/o:brother:mfc-j5320dw_firmware",
                     "cpe:/o:brother:mfc-j5330dw_firmware",
                     "cpe:/o:brother:mfc-j5335dw_firmware",
                     "cpe:/o:brother:mfc-j5520dw_firmware",
                     "cpe:/o:brother:mfc-j5620cdw_firmware",
                     "cpe:/o:brother:mfc-j5620dw_firmware",
                     "cpe:/o:brother:mfc-j5625dw_firmware",
                     "cpe:/o:brother:mfc-j5630cdw_firmware",
                     "cpe:/o:brother:mfc-j5720dw_firmware",
                     "cpe:/o:brother:mfc-j5730dw_firmware",
                     "cpe:/o:brother:mfc-j5820dn_firmware",
                     "cpe:/o:brother:mfc-j5830dw_firmware",
                     "cpe:/o:brother:mfc-j5920dw_firmware",
                     "cpe:/o:brother:mfc-j5930dw_firmware",
                     "cpe:/o:brother:mfc-j6530dw_firmware",
                     "cpe:/o:brother:mfc-j6535dw_firmware",
                     "cpe:/o:brother:mfc-j6580cdw_firmware",
                     "cpe:/o:brother:mfc-j6583cdw_firmware",
                     "cpe:/o:brother:mfc-j6730dw_firmware",
                     "cpe:/o:brother:mfc-j680dw_firmware",
                     "cpe:/o:brother:mfc-j690dw_firmware",
                     "cpe:/o:brother:mfc-j6930dw_firmware",
                     "cpe:/o:brother:mfc-j6935dw_firmware",
                     "cpe:/o:brother:mfc-j6980cdw_firmware",
                     "cpe:/o:brother:mfc-j6983cdw_firmware",
                     "cpe:/o:brother:mfc-j6995cdw_firmware",
                     "cpe:/o:brother:mfc-j730dn_firmware",
                     "cpe:/o:brother:mfc-j730dwn_firmware",
                     "cpe:/o:brother:mfc-j737dn_firmware",
                     "cpe:/o:brother:mfc-j737dwn_firmware",
                     "cpe:/o:brother:mfc-j738dn_firmware",
                     "cpe:/o:brother:mfc-j738dwn_firmware",
                     "cpe:/o:brother:mfc-j775dw_firmware",
                     "cpe:/o:brother:mfc-j830dn_firmware",
                     "cpe:/o:brother:mfc-j830dwn_firmware",
                     "cpe:/o:brother:mfc-j837dn_firmware",
                     "cpe:/o:brother:mfc-j837dn_firmware",
                     "cpe:/o:brother:mfc-j880dw_firmware",
                     "cpe:/o:brother:mfc-j880n_firmware",
                     "cpe:/o:brother:mfc-j885dw_firmware",
                     "cpe:/o:brother:mfc-j887n_firmware",
                     "cpe:/o:brother:mfc-j890dw_firmware",
                     "cpe:/o:brother:mfc-j893n_firmware",
                     "cpe:/o:brother:mfc-j895dw_firmware",
                     "cpe:/o:brother:mfc-j898n_firmware",
                     "cpe:/o:brother:mfc-j900dn_firmware",
                     "cpe:/o:brother:mfc-j900dwn_firmware",
                     "cpe:/o:brother:mfc-j903n_firmware",
                     "cpe:/o:brother:mfc-j907dn_firmware",
                     "cpe:/o:brother:mfc-j907dwn_firmware",
                     "cpe:/o:brother:mfc-j985dw_firmware",
                     "cpe:/o:brother:mfc-j990dn_firmware",
                     "cpe:/o:brother:mfc-j990dwn_firmware",
                     "cpe:/o:brother:mfc-j997dn_firmware",
                     "cpe:/o:brother:mfc-j997dwn_firmware",
                     "cpe:/o:brother:mfc-j998dn_firmware",
                     "cpe:/o:brother:mfc-j998dwn_firmware",
                     "cpe:/o:brother:mfc-l2680w_firmware",
                     "cpe:/o:brother:mfc-l2685dw_firmware",
                     "cpe:/o:brother:mfc-l2700dn_firmware",
                     "cpe:/o:brother:mfc-l2700dnr_firmware",
                     "cpe:/o:brother:mfc-l2700dw_firmware",
                     "cpe:/o:brother:mfc-l2700dwr_firmware",
                     "cpe:/o:brother:mfc-l2701dw_firmware",
                     "cpe:/o:brother:mfc-l2703dw_firmware",
                     "cpe:/o:brother:mfc-l2705dw_firmware",
                     "cpe:/o:brother:mfc-l2707dw_firmware",
                     "cpe:/o:brother:mfc-l2720dn_firmware",
                     "cpe:/o:brother:mfc-l2720dw_firmware",
                     "cpe:/o:brother:mfc-l2720dwr_firmware",
                     "cpe:/o:brother:mfc-l2740dw_firmware",
                     "cpe:/o:brother:mfc-l2740dwr_firmware",
                     "cpe:/o:brother:mfc-l8610cdw_firmware",
                     "cpe:/o:brother:mfc-l8690cdw_firmware",
                     "cpe:/o:brother:mfc-l8900cdw_firmware",
                     "cpe:/o:brother:mfc-l9570cdw_firmware",
                     "cpe:/o:brother:mfc-l9577cdw_firmware",
                     "cpe:/o:brother:mfc-t810w_firmware",
                     "cpe:/o:brother:mfc-t910dw_firmware");

if (!infos = get_app_version_from_list(cpe_list: cpe_list, nofork: TRUE))
  exit(0);

version = infos["version"];
cpe = infos["cpe"];

if (cpe =~ "^cpe:/o:brother:dcp-161[02](w|we|wvb)_firmware" ||
    cpe == "cpe:/o:brother:dcp-1622we_firmware" ||
    cpe =~ "^cpe:/o:brother:dcp-1623w[er]_firmware") {
  if (version_is_less(version: version, test_version: "Z")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "Z");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:brother:dcp-161[567]nw_firmware") {
  if (version_is_less(version: version, test_version: "R")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "R");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:brother:dcp-1618w_firmware" ||
    cpe == "cpe:/o:brother:dcp-7180dn_firmware") {
  if (version_is_less(version: version, test_version: "P")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "P");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:brother:dcp-j4120dw_firmware" ||
    cpe =~ "^cpe:/o:brother:dcp-j4220n-[bw]_firmware") {
  if (version_is_less(version: version, test_version: "M")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "M");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:brother:dcp-j4225n-[bw]_firmware") {
  if (version_is_less(version: version, test_version: "H")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "H");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:brother:dcp-j562dw_firmware") {
  if (version_is_less(version: version, test_version: "L")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "L");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:brother:dcp-j56[27]n_firmware") {
  if (version_is_less(version: version, test_version: "K")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "K");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:brother:dcp-j572dw_firmware") {
  if (version_is_less(version: version, test_version: "N")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "N");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:brother:dcp-j57[27]n_firmware" ||
    cpe == "cpe:/o:brother:dcp-j582n_firmware") {
  if (version_is_less(version: version, test_version: "V")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "V");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:brother:dcp-j587n_firmware") {
  if (version_is_less(version: version, test_version: "E")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "E");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:brother:dcp-j76[27]n_firmware" ||
    cpe == "cpe:/o:brother:dcp-j962n_firmware" ||
    cpe =~ "^cpe:/o:brother:dcp-j96[38]n-[bw]_firmware") {
  if (version_is_less(version: version, test_version: "P")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "P");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:brother:dcp-j77[24]dw_firmware") {
  if (version_is_less(version: version, test_version: "S")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "S");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:brother:dcp-j785dw_firmware") {
  if (version_is_less(version: version, test_version: "G")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "G");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:brother:dcp-j972n_firmware" ||
    cpe =~ "^cpe:/o:brother:dcp-j97[38]n-[bw]_firmware" ||
    cpe == "cpe:/o:brother:dcp-j981n_firmware" ||
    cpe =~ "^cpe:/o:brother:dcp-j982n-[bw]_firmware") {
  if (version_is_less(version: version, test_version: "X")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "X");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:brother:dcp-j983n_firmware") {
  if (version_is_less(version: version, test_version: "P")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "P");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:brother:dcp-j987n-[bw]_firmware") {
  if (version_is_less(version: version, test_version: "E")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "E");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:brother:dcp-l2520(dw|dwr)_firmware") {
  if (version_is_less(version: version, test_version: "W")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "W");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:brother:dcp-l2540(dn|dnr|dw)_firmware" ||
    cpe == "cpe:/o:brother:dcp-l2541dw_firmware") {
  if (version_is_less(version: version, test_version: "X")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "X");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:brother:dcp-l2541(dw|dwr)_firmware") {
  if (version_is_less(version: version, test_version: "V")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "V");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:brother:dcp-l8410cdw_firmware") {
  if (version_is_less(version: version, test_version: "G")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "G");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "cpe:/o:brother:dcp-t[57]10w_firmware") {
  if (version_is_less(version: version, test_version: "P")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "P");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:brother:fax-l2700dn_firmware") {
  if (version_is_less(version: version, test_version: "Q")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "Q");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:brother:hl-121[02](w|we|wr|wvb)_firmware" ||
    cpe =~ "^cpe:/o:brother:hl-121[18]w_firmware" ||
    cpe =~ "^cpe:/o:brother:hl-122[23]we_firmware" ||
    cpe == "cpe:/o:brother:hl-1223wr_firmware") {
  if (version_is_less(version: version, test_version: "1.20")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "1.20");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:brother:hl-2560dn_firmware" ||
    cpe =~ "^cpe:/o:brother:hl-l2360(dn|dnr|dw)_firmware" ||
    cpe == "cpe:/o:brother:hl-2361dn_firmware" ||
    cpe =~ "^cpe:/o:brother:hl-l2365(dw|dwr)_firmware" ||
    cpe == "cpe:/o:brother:hl-2366dw_firmware") {
  if (version_is_less(version: version, test_version: "1.35")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "1.35");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:brother:hl-l2305w_firmware" ||
    cpe == "cpe:/o:brother:hl-l2315dw_firmware") {
  if (version_is_less(version: version, test_version: "1.24")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "1.24");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:brother:hl-l2340(dw|dwr)_firmware") {
  if (version_is_less(version: version, test_version: "1.26")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "1.26");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:brother:hl-l2380dw_firmware") {
  if (version_is_less(version: version, test_version: "V")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "V");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:brother:hl-l8260cd[nw]_firmware") {
  if (version_is_less(version: version, test_version: "1.15")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "1.15");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:brother:hl-l8360(cdw|cdwt)_firmware" ||
    cpe == "cpe:/o:brother:hl-l9310cdw_firmware") {
  if (version_is_less(version: version, test_version: "1.20")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "1.20");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:brother:mfc-1910(w|we)_firmware" ||
    cpe =~ "^cpe:/o:brother:mfc-1911(nw|w)_firmware" ||
    cpe == "cpe:/o:brother:mfc-1912wr_firmware" ||
    cpe == "cpe:/o:brother:mfc-1915w_firmware" ||
    cpe == "cpe:/o:brother:mfc-1916nw_firmware") {
  if (version_is_less(version: version, test_version: "T")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "T");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:brother:mfc-1919nw_firmware") {
  if (version_is_less(version: version, test_version: "P")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "P");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:brother:mfc-7880dn_firmware" ||
    cpe == "cpe:/o:brother:mfc-j2720_firmware") {
  if (version_is_less(version: version, test_version: "Q")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "Q");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:brother:mfc-j2320_firmware") {
  if (version_is_less(version: version, test_version: "L")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "L");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:brother:mfc-j2330dw_firmware" ||
    cpe == "cpe:/o:brother:mfc-j3530dw_firmware") {
  if (version_is_less(version: version, test_version: "W")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "W");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:brother:mfc-j2730dw_firmware") {
  if (version_is_less(version: version, test_version: "Y")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "Y");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:brother:mfc-j3930dw_firmware") {
  if (version_is_less(version: version, test_version: "Z")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "Z");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:brother:mfc-j4[34]20dw_firmware") {
  if (version_is_less(version: version, test_version: "Z")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "Z");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:brother:mfc-j4[68]0dw_firmware" ||
    cpe == "cpe:/o:brother:mfc-j485dw_firmware" ||
    cpe =~ "^cpe:/o:brother:mfc-j49[17]dw_firmware") {
  if (version_is_less(version: version, test_version: "P")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "P");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:brother:mfc-j462[05]dw_firmware") {
  if (version_is_less(version: version, test_version: "U")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "U");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:brother:mfc-j4720n_firmware") {
  if (version_is_less(version: version, test_version: "M")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "M");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:brother:mfc-j4725n_firmware") {
  if (version_is_less(version: version, test_version: "H")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "H");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:brother:mfc-j4725n_firmware") {
  if (version_is_less(version: version, test_version: "L")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "L");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:brother:mfc-j533[05]dw_firmware") {
  if (version_is_less(version: version, test_version: "W")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "W");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:brother:mfc-j5520dw_firmware" ||
    cpe =~ "^cpe:/o:brother:mfc-j562[05]dw_firmware") {
  if (version_is_less(version: version, test_version: "R")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "R");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:brother:mfc-j5620cdw_firmware") {
  if (version_is_less(version: version, test_version: "J")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "J");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:brother:mfc-j5[79]20dw_firmware") {
  if (version_is_less(version: version, test_version: "Q")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "Q");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:brother:mfc-j5[789]30dw_firmware") {
  if (version_is_less(version: version, test_version: "Y")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "Y");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:brother:mfc-j5820dn_firmware") {
  if (version_is_less(version: version, test_version: "K")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "K");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:brother:mfc-j6[57]30dw_firmware") {
  if (version_is_less(version: version, test_version: "W")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "W");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:brother:mfc-j6[59]35dw_firmware" ||
    cpe == "cpe:/o:brother:mfc-j6930dw_firmware") {
  if (version_is_less(version: version, test_version: "Z")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "Z");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:brother:mfc-j6580cdw_firmware") {
  if (version_is_less(version: version, test_version: "R")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "R");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:brother:mfc-j6583cdw_firmware" ||
    cpe == "cpe:/o:brother:mfc-j680dw_firmware") {
  if (version_is_less(version: version, test_version: "K")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "K");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:brother:mfc-j6980cdw_firmware" ||
    cpe == "cpe:/o:brother:mfc-j690dw_firmware" ||
    cpe == "cpe:/o:brother:mfc-j6995cdw_firmware") {
  if (version_is_less(version: version, test_version: "S")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "S");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:brother:mfc-j693[05]dw_firmware") {
  if (version_is_less(version: version, test_version: "Z")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "Z");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:brother:mfc-j6983cdw_firmware") {
  if (version_is_less(version: version, test_version: "M")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "M");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:brother:mfc-j73[078](dn|dwn)_firmware") {
  if (version_is_less(version: version, test_version: "L")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "L");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:brother:mfc-j775dw_firmware" ||
    cpe =~ "^cpe:/o:brother:mfc-j88[05]dw_firmware") {
  if (version_is_less(version: version, test_version: "P")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "P");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:brother:mfc-j83[07](dn|dwn)_firmware" ||
    cpe =~ "^cpe:/o:brother:mfc-j88[07]n_firmware") {
  if (version_is_less(version: version, test_version: "K")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "K");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:brother:mfc-j89[05]dw_firmware") {
  if (version_is_less(version: version, test_version: "S")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "S");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:brother:mfc-j89[38]n_firmware" ||
    cpe == "cpe:/o:brother:mfc-j903n_firmware") {
  if (version_is_less(version: version, test_version: "W")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "W");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:brother:mfc-j90[07](dn|dwn)_firmware") {
  if (version_is_less(version: version, test_version: "K")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "K");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:brother:mfc-j985dw_firmware") {
  if (version_is_less(version: version, test_version: "P")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "P");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:brother:mfc-j99[07](dn|dwn)_firmware") {
  if (version_is_less(version: version, test_version: "M")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "M");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:brother:mfc-l2680w_firmware" ||
    cpe == "cpe:/o:brother:mfc-l2685dw_firmware" ||
    cpe =~ "^cpe:/o:brother:mfc-l2700(dn|dnr|dw|dwr)_firmware") {
  if (version_is_less(version: version, test_version: "X")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "X");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:brother:mfc-l270[1357]dw_firmware" ||
    cpe =~ "^cpe:/o:brother:mfc-l2740(dw|dwr)_firmware") {
  if (version_is_less(version: version, test_version: "V")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "V");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:brother:mfc-l2720dn_firmware") {
  if (version_is_less(version: version, test_version: "S")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "S");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:brother:mfc-l2720(dw|dwr)_firmware") {
  if (version_is_less(version: version, test_version: "W")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "W");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:brother:mfc-l8(61|69|90)0cdw_firmware" ||
    cpe =~ "^cpe:/o:brother:mfc-l957[07]cdw_firmware") {
  if (version_is_less(version: version, test_version: "G")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "G");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:brother:mfc-t810w_firmware" ||
    cpe == "cpe:/o:brother:mfc-t910dw_firmware") {
  if (version_is_less(version: version, test_version: "P")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "P");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);
