# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.170532");
  script_version("2023-08-10T05:05:53+0000");
  script_tag(name:"last_modification", value:"2023-08-10 05:05:53 +0000 (Thu, 10 Aug 2023)");
  script_tag(name:"creation_date", value:"2023-08-08 13:28:00 +0000 (Tue, 08 Aug 2023)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_cve_id("CVE-2023-29984");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Fuji Xerox/Fujifilm Printers DoS Vulnerability (Jul 2023)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("General");
  script_dependencies("gb_fujifilm_printer_consolidation.nasl");
  script_mandatory_keys("fujifilm/printer/detected");

  script_tag(name:"summary", value:"Multiple Fuji Xerox / Fujifilm printers are prone to a denial of service
  (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable firmware version is present on the target host.");

  script_tag(name:"insight", value:"Processing a specially crafted request may lead an affected product to a
  denial of service condition.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_xref(name:"URL", value:"https://www.fujifilm.com/fbglobal/eng/company/news/notice/2023/browser_announce.html");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

cpe_list = make_list("cpe:/o:fujifilm:docuprint_p115_w_firmware",
                     "cpe:/o:fujifilm:docuprint_p118_w_firmware",
                     "cpe:/o:fujifilm:docuprint_m115_w_firmware",
                     "cpe:/o:fujifilm:docuprint_m115_fw_firmware",
                     "cpe:/o:fujifilm:docuprint_m115_z_firmware",
                     "cpe:/o:fujifilm:docuprint_m118_w_firmware",
                     "cpe:/o:fujifilm:docuprint_m118_z_firmware",
                     "cpe:/o:fujifilm:docuprint_p225_d_firmware",
                     "cpe:/o:fujifilm:docuprint_p268_d_firmware",
                     "cpe:/o:fujifilm:docuprint_p268_dw_firmware",
                     "cpe:/o:fujifilm:docuprint_p265_dw_firmware",
                     "cpe:/o:fujifilm:docuprint_m268_dw_firmware",
                     "cpe:/o:fujifilm:docuprint_m225_dw_firmware",
                     "cpe:/o:fujifilm:docuprint_m225_z_firmware",
                     "cpe:/o:fujifilm:docuprint_m268_z_firmware",
                     "cpe:/o:fujifilm:docuprint_m265_z_firmware");

if (!infos = get_app_version_from_list(cpe_list: cpe_list, nofork: TRUE))
  exit(0);

version = infos["version"];
cpe = infos["cpe"];

if (cpe == "cpe:/o:fujifilm:docuprint_p115_w_firmware") {
  if (version_is_less(version: version, test_version: "1.11")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "1.11");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:fujifilm:docuprint_m11[58]_[wz]_firmware" ||
    cpe == "cpe:/o:fujifilm:docuprint_p118_w_firmware" ||
    cpe == "cpe:/o:fujifilm:docuprint_m115_fw_firmware" ||
    cpe =~ "cpe:/o:fujifilm:docuprint_m268_(dw|z)_firmware") {
  if (version_is_less(version: version, test_version: "L")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "L");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:fujifilm:docuprint_p225_d_firmware") {
  if (version_is_less(version: version, test_version: "1.17")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "1.17");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:fujifilm:docuprint_p26[58]_dw_firmware" ||
    cpe == "cpe:/o:fujifilm:docuprint_p268_d_firmware") {
  if (version_is_less(version: version, test_version: "1.21")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "1.21");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:fujifilm:docuprint_m265_z_firmware" ||
    cpe =~ "cpe:/o:fujifilm:docuprint_m225_(dw|z)_firmware") {
  if (version_is_less(version: version, test_version: "N")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "N");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);