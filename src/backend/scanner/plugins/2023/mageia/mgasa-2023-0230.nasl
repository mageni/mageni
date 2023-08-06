# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2023.0230");
  script_cve_id("CVE-2021-26291");
  script_tag(name:"creation_date", value:"2023-07-20 04:12:53 +0000 (Thu, 20 Jul 2023)");
  script_version("2023-07-20T05:05:17+0000");
  script_tag(name:"last_modification", value:"2023-07-20 05:05:17 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-07-20 11:15:00 +0000 (Tue, 20 Jul 2021)");

  script_name("Mageia: Security Advisory (MGASA-2023-0230)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2023-0230");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2023-0230.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=28924");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2021/04/23/5");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5805-1");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2023-May/014769.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'maven' package(s) announced via the MGASA-2023-0230 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"No longer use http (non-SSL) repository references by default.");

  script_tag(name:"affected", value:"'maven' package(s) on Mageia 8.");

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

  if(!isnull(res = isrpmvuln(pkg:"maven", rpm:"maven~3.6.3~8.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-javadoc", rpm:"maven-javadoc~3.6.3~8.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-lib", rpm:"maven-lib~3.6.3~8.1.mga8", rls:"MAGEIA8"))) {
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
