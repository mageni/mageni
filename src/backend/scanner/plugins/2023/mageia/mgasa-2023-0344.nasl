# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2023.0344");
  script_cve_id("CVE-2023-49284");
  script_tag(name:"creation_date", value:"2023-12-13 04:12:33 +0000 (Wed, 13 Dec 2023)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:R/S:U/C:H/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-12-08 17:26:11 +0000 (Fri, 08 Dec 2023)");

  script_name("Mageia: Security Advisory (MGASA-2023-0344)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA(8|9)");

  script_xref(name:"Advisory-ID", value:"MGASA-2023-0344");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2023-0344.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=32614");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'fish' package(s) announced via the MGASA-2023-0344 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Mageia 9 is updated to version 3.6.4 to fix CVE-2023-49284.
Mageia 8 receives an upstream patch to fix CVE-2023-49284.
CVE-2023-49284: fish shell uses certain Unicode non-characters
internally for marking wildcards and expansions. It will incorrectly
allow these markers to be read on command substitution output, rather
than transforming them into a safe internal representation.");

  script_tag(name:"affected", value:"'fish' package(s) on Mageia 8, Mageia 9.");

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

  if(!isnull(res = isrpmvuln(pkg:"fish", rpm:"fish~3.4.1~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "MAGEIA9") {

  if(!isnull(res = isrpmvuln(pkg:"fish", rpm:"fish~3.6.4~1.mga9", rls:"MAGEIA9"))) {
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
