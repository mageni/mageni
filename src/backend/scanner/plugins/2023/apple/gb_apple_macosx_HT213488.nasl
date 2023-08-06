# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only


if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.832335");
  script_version("2023-07-28T16:09:07+0000");
  script_cve_id("CVE-2022-42795", "CVE-2022-32858", "CVE-2022-32898", "CVE-2022-32899", "CVE-2022-32907",
                "CVE-2022-32827", "CVE-2022-32877", "CVE-2022-42789", "CVE-2022-42825", "CVE-2022-32902",
                "CVE-2022-32904", "CVE-2022-32890", "CVE-2022-42796", "CVE-2022-42798", "CVE-2022-32940",
                "CVE-2022-42821", "CVE-2022-42860", "CVE-2022-42819", "CVE-2022-42813", "CVE-2022-26730",
                "CVE-2022-32945", "CVE-2022-42838", "CVE-2022-22663", "CVE-2022-32867", "CVE-2022-32205",
                "CVE-2022-32206", "CVE-2022-32207", "CVE-2022-32208", "CVE-2022-42814", "CVE-2022-32865",
                "CVE-2022-32915", "CVE-2022-32928", "CVE-2022-22643", "CVE-2022-32935", "CVE-2022-42788",
                "CVE-2022-32905", "CVE-2022-42833", "CVE-2022-32947", "CVE-2022-42809", "CVE-2022-3437",
                "CVE-2022-32849", "CVE-2022-32913", "CVE-2022-1622", "CVE-2022-32936", "CVE-2022-42820",
                "CVE-2022-42806", "CVE-2022-32864", "CVE-2022-32866", "CVE-2022-32911", "CVE-2022-32924",
                "CVE-2022-32914", "CVE-2022-42808", "CVE-2022-32944", "CVE-2022-42803", "CVE-2022-32926",
                "CVE-2022-42801", "CVE-2022-46712", "CVE-2022-42815", "CVE-2022-42834", "CVE-2022-42800",
                "CVE-2022-32883", "CVE-2022-32908", "CVE-2022-42810", "CVE-2021-39537", "CVE-2022-29458",
                "CVE-2022-42818", "CVE-2022-32879", "CVE-2022-32895", "CVE-2022-46713", "CVE-2022-42807",
                "CVE-2022-32918", "CVE-2022-42829", "CVE-2022-42830", "CVE-2022-42831", "CVE-2022-42832",
                "CVE-2022-32941", "CVE-2022-28739", "CVE-2022-32881", "CVE-2022-32862", "CVE-2022-42811",
                "CVE-2022-42793", "CVE-2022-32938", "CVE-2022-42790", "CVE-2022-32870", "CVE-2022-32934",
                "CVE-2022-42791", "CVE-2021-36690", "CVE-2022-48505", "CVE-2022-0261", "CVE-2022-0318",
                "CVE-2022-0319", "CVE-2022-0351", "CVE-2022-0359", "CVE-2022-0361", "CVE-2022-0368",
                "CVE-2022-0392", "CVE-2022-0554", "CVE-2022-0572", "CVE-2022-0629", "CVE-2022-0685",
                "CVE-2022-0696", "CVE-2022-0714", "CVE-2022-0729", "CVE-2022-0943", "CVE-2022-1381",
                "CVE-2022-1420", "CVE-2022-1725", "CVE-2022-1616", "CVE-2022-1619", "CVE-2022-1620",
                "CVE-2022-1621", "CVE-2022-1629", "CVE-2022-1674", "CVE-2022-1733", "CVE-2022-1735",
                "CVE-2022-1769", "CVE-2022-1927", "CVE-2022-1942", "CVE-2022-1968", "CVE-2022-1851",
                "CVE-2022-1897", "CVE-2022-1898", "CVE-2022-1720", "CVE-2022-2000", "CVE-2022-2042",
                "CVE-2022-2124", "CVE-2022-2125", "CVE-2022-2126", "CVE-2022-32875", "CVE-2022-42826",
                "CVE-2022-32886", "CVE-2022-32888", "CVE-2022-32912", "CVE-2022-42799", "CVE-2022-42823",
                "CVE-2022-42824", "CVE-2022-32923", "CVE-2022-32922", "CVE-2022-32892", "CVE-2022-32833",
                "CVE-2022-46709", "CVE-2022-37434");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-07-28 16:09:07 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-07-15 03:15:00 +0000 (Fri, 15 Jul 2022)");
  script_tag(name:"creation_date", value:"2023-07-25 15:52:56 +0530 (Tue, 25 Jul 2023)");
  script_name("Apple MacOSX Security Updates (HT213488)");

  script_tag(name:"summary", value:"Apple Mac OS X is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - An improper state and memory management.

  - Improper code signature verification validation within memory.

  - Improper handling of bound checks.

  - Improper access restriction policies.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to conduct arbitrary code execution, bypass security restrictions and disclose
  sensitive information on an affected system.");

  script_tag(name:"affected", value:"Apple Mac OS X versions prior to
  version 13.");

  script_tag(name:"solution", value:"Upgrade to version 13 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT213488");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Mac OS X Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/osx_name", "ssh/login/osx_version", re:"ssh/login/osx_version=^13\.");
  exit(0);
}

include("version_func.inc");

osName = get_kb_item("ssh/login/osx_name");
if(!osName)
  exit(0);

osVer = get_kb_item("ssh/login/osx_version");
if(!osVer || osVer !~ "^13\." || "Mac OS X" >!< osName) {
  exit(0);
}

if(version_is_less(version:osVer, test_version:"13")) {
  report = report_fixed_ver(installed_version:osVer, fixed_version:"13");

  security_message(port:0, data:report);
  exit(0);
}

exit(99);
