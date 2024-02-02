# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2023.0325");
  script_cve_id("CVE-2020-17354");
  script_tag(name:"creation_date", value:"2023-11-28 04:12:25 +0000 (Tue, 28 Nov 2023)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-04-25 16:52:41 +0000 (Tue, 25 Apr 2023)");

  script_name("Mageia: Security Advisory (MGASA-2023-0325)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2023-0325");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2023-0325.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=31889");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'lilypond' package(s) announced via the MGASA-2023-0325 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated lilypond packages fix a security vulnerability:

LilyPond before 2.24 allows attackers to bypass the -dsafe protection
mechanism via output-def-lookup or output-def-scope, as demonstrated by
dangerous Scheme code in a .ly file that causes arbitrary code execution
during conversion to a different file format. NOTE: in 2.24 and later
versions, safe mode is removed, and the product no longer tries to block
code execution when external files are used.");

  script_tag(name:"affected", value:"'lilypond' package(s) on Mageia 9.");

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

if(release == "MAGEIA9") {

  if(!isnull(res = isrpmvuln(pkg:"lilypond", rpm:"lilypond~2.24.2~2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lilypond-doc", rpm:"lilypond-doc~2.24.2~2.mga9", rls:"MAGEIA9"))) {
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
