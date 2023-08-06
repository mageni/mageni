# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2023.0220");
  script_cve_id("CVE-2022-4065");
  script_tag(name:"creation_date", value:"2023-07-10 04:12:52 +0000 (Mon, 10 Jul 2023)");
  script_version("2023-07-10T08:07:42+0000");
  script_tag(name:"last_modification", value:"2023-07-10 08:07:42 +0000 (Mon, 10 Jul 2023)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-11-26 03:24:00 +0000 (Sat, 26 Nov 2022)");

  script_name("Mageia: Security Advisory (MGASA-2023-0220)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2023-0220");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2023-0220.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=31741");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2023-March/014264.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'testng' package(s) announced via the MGASA-2023-0220 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Path traversal in zip files (CVE-2022-4065)");

  script_tag(name:"affected", value:"'testng' package(s) on Mageia 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "MAGEIA8") {

  if(!isnull(res = isrpmvuln(pkg:"testng", rpm:"testng~6.14.3~4.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"testng-javadoc", rpm:"testng-javadoc~6.14.3~4.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);
