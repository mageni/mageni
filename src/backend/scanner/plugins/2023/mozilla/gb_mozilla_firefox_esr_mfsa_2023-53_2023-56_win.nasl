# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:firefox_esr";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.832748");
  script_version("2023-12-26T05:05:23+0000");
  script_cve_id("CVE-2023-6856", "CVE-2023-6865", "CVE-2023-6858", "CVE-2023-6859",
                "CVE-2023-6860", "CVE-2023-6867", "CVE-2023-6861", "CVE-2023-6862",
                "CVE-2023-6863", "CVE-2023-6864");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-12-26 05:05:23 +0000 (Tue, 26 Dec 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-12-22 10:59:00 +0000 (Fri, 22 Dec 2023)");
  script_tag(name:"creation_date", value:"2023-12-21 14:27:05 +0530 (Thu, 21 Dec 2023)");
  script_name("Mozilla Firefox ESR Security Update (mfsa_2023-53_2023-56) - Windows");

  script_tag(name:"summary", value:"Mozilla Firefox ESR is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - Heap-buffer-overflow affecting WebGL DrawElementsInstanced method with Mesa VM driver.

  - Potential exposure of uninitialized data in EncryptingOutputStream.

  For more information about the vulnerabilities refer to Reference links.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to execute arbitrary code, conduct heap buffer overflow, information
  disclosure and cause denial of service on an affected system.");

  script_tag(name:"affected", value:"Mozilla Firefox ESR version before
  115.6 on Windows.");

  script_tag(name:"solution", value:"Upgrade to version 115.6 or later,
  Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2023-54/");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("General");
  script_dependencies("gb_firefox_detect_win.nasl");
  script_mandatory_keys("Firefox-ESR/Win/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit( 0 );

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"115.6")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"115.6", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}
