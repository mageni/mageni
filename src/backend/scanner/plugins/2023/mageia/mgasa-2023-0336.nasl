# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2023.0336");
  script_cve_id("CVE-2022-24599");
  script_tag(name:"creation_date", value:"2023-12-04 12:33:48 +0000 (Mon, 04 Dec 2023)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-03-03 16:29:16 +0000 (Thu, 03 Mar 2022)");

  script_name("Mageia: Security Advisory (MGASA-2023-0336)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2023-0336");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2023-0336.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=32561");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/WTETOUJNRR75REYJZTBGF6TAJZYTMXUY/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'audiofile' package(s) announced via the MGASA-2023-0336 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The updated packages fix a security vulnerability

In autofile Audio File Library 0.3.6, there exists one memory leak
vulnerability in printfileinfo, in printinfo.c, which allows an attacker
to leak sensitive information via a crafted file. The printfileinfo
function calls the copyrightstring function to get data, however, it
dosn't use zero bytes to truncate the data. (CVE-2022-24599)");

  script_tag(name:"affected", value:"'audiofile' package(s) on Mageia 9.");

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

  if(!isnull(res = isrpmvuln(pkg:"audiofile", rpm:"audiofile~0.3.6~12.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64audiofile-devel", rpm:"lib64audiofile-devel~0.3.6~12.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64audiofile1", rpm:"lib64audiofile1~0.3.6~12.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libaudiofile-devel", rpm:"libaudiofile-devel~0.3.6~12.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libaudiofile1", rpm:"libaudiofile1~0.3.6~12.1.mga9", rls:"MAGEIA9"))) {
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
