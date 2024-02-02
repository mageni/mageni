# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only


if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.832614");
  script_version("2024-01-29T05:05:18+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2023-23495", "CVE-2023-29497", "CVE-2023-32361", "CVE-2023-32377",
                "CVE-2023-32396", "CVE-2023-32421", "CVE-2023-35074", "CVE-2023-35984",
                "CVE-2023-35990", "CVE-2023-37448", "CVE-2023-38586", "CVE-2023-38596",
                "CVE-2023-38615", "CVE-2023-39233", "CVE-2023-39434", "CVE-2023-40384",
                "CVE-2023-40386", "CVE-2023-40388", "CVE-2023-40391", "CVE-2023-40395",
                "CVE-2023-40399", "CVE-2023-40400", "CVE-2023-40402", "CVE-2023-40403",
                "CVE-2023-40406", "CVE-2023-40407", "CVE-2023-40410", "CVE-2023-40417",
                "CVE-2023-40420", "CVE-2023-40422", "CVE-2023-40424", "CVE-2023-40426",
                "CVE-2023-40427", "CVE-2023-40429", "CVE-2023-40432", "CVE-2023-40434",
                "CVE-2023-40436", "CVE-2023-40441", "CVE-2023-40448", "CVE-2023-40450",
                "CVE-2023-40452", "CVE-2023-40454", "CVE-2023-40455", "CVE-2023-40541",
                "CVE-2023-41063", "CVE-2023-41065", "CVE-2023-41066", "CVE-2023-41067",
                "CVE-2023-41070", "CVE-2023-41073", "CVE-2023-41074", "CVE-2023-41078",
                "CVE-2023-41079", "CVE-2023-41968", "CVE-2023-41979", "CVE-2023-41980",
                "CVE-2023-41981", "CVE-2023-41984", "CVE-2023-41986", "CVE-2023-41993",
                "CVE-2023-41995", "CVE-2023-42826", "CVE-2023-38612", "CVE-2023-38607",
                "CVE-2023-38610", "CVE-2023-40385", "CVE-2023-40393", "CVE-2023-40411",
                "CVE-2023-40414", "CVE-2023-40430", "CVE-2023-40438", "CVE-2023-41060",
                "CVE-2023-41987", "CVE-2023-41994", "CVE-2023-42934", "CVE-2023-42933",
                "CVE-2023-42929", "CVE-2023-42876", "CVE-2023-42872", "CVE-2023-42871",
                "CVE-2023-42870", "CVE-2023-42833");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-01-29 05:05:18 +0000 (Mon, 29 Jan 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-09-29 04:29:00 +0000 (Fri, 29 Sep 2023)");
  script_tag(name:"creation_date", value:"2023-10-27 13:07:18 +0530 (Fri, 27 Oct 2023)");
  script_name("Apple MacOSX Security Update (HT213940)");

  script_tag(name:"summary", value:"Apple Mac OS X is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - An improper redaction of sensitive information.

  - Improper checks.

  - Improper handling of caches, protocols.

  - Existence of vulnerable code.

  - An improper input validation.

  - An improper memory handling.

  For more information about the vulnerabilities refer to Reference links.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to conduct spoofing, arbitrary code execution, denial of service, information disclosure.");

  script_tag(name:"affected", value:"Apple macOS versions prior to version 14");

  script_tag(name:"solution", value:"Upgrade to version 14 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT213940");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Mac OS X Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/osx_name", "ssh/login/osx_version");
  exit(0);
}

include("version_func.inc");

osName = get_kb_item("ssh/login/osx_name");
if(!osName)
  exit(0);

osVer = get_kb_item("ssh/login/osx_version");
if(!osVer || "Mac OS X" >!< osName) {
  exit(0);
}

if(version_is_less(version:osVer, test_version:"14.0")) {
  report = report_fixed_ver(installed_version:osVer, fixed_version:"14.0");
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
