# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2023.0347");
  script_cve_id("CVE-2019-13147");
  script_tag(name:"creation_date", value:"2023-12-18 04:13:00 +0000 (Mon, 18 Dec 2023)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-07-03 17:26:00 +0000 (Wed, 03 Jul 2019)");

  script_name("Mageia: Security Advisory (MGASA-2023-0347)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2023-0347");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2023-0347.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=32608");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'audiofile' package(s) announced via the MGASA-2023-0347 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"2 patches are added to audiofile source to correct a vulnerability.
In Audio File Library (aka audiofile) 0.3.6, there exists one NULL
pointer dereference bug in ulaw2linear_buf in G711.cpp in libmodules.a
that allows an attacker to cause a denial of service via a crafted file.
(CVE-2019-13147)");

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

  if(!isnull(res = isrpmvuln(pkg:"audiofile", rpm:"audiofile~0.3.6~14.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64audiofile-devel", rpm:"lib64audiofile-devel~0.3.6~14.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64audiofile1", rpm:"lib64audiofile1~0.3.6~14.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libaudiofile-devel", rpm:"libaudiofile-devel~0.3.6~14.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libaudiofile1", rpm:"libaudiofile1~0.3.6~14.mga9", rls:"MAGEIA9"))) {
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
