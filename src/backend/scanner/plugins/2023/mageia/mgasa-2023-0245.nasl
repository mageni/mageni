# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2023.0245");
  script_cve_id("CVE-2022-23471", "CVE-2023-25153", "CVE-2023-25173");
  script_tag(name:"creation_date", value:"2023-08-24 04:11:47 +0000 (Thu, 24 Aug 2023)");
  script_version("2023-08-24T05:06:01+0000");
  script_tag(name:"last_modification", value:"2023-08-24 05:06:01 +0000 (Thu, 24 Aug 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-02-24 16:56:00 +0000 (Fri, 24 Feb 2023)");

  script_name("Mageia: Security Advisory (MGASA-2023-0245)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2023-0245");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2023-0245.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=31268");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2022-December/013215.html");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5776-1");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/J2URKEEXLEABIVVVLSCXEXL6GIXX3GYN/");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/7KYYYEETR5DEGOQBCMLUC4OEN4O3JGKF/");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6202-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'docker-containerd, golang-github-mrunalp-fileutils' package(s) announced via the MGASA-2023-0245 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Memory leak. (CVE-2022-23471)
Denial of service with maliciously crafted image with a large file
(CVE-2023-25153)
Security bypass due to improper supplementary group handling.
(CVE-2023-25173)");

  script_tag(name:"affected", value:"'docker-containerd, golang-github-mrunalp-fileutils' package(s) on Mageia 8.");

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

  if(!isnull(res = isrpmvuln(pkg:"docker-containerd", rpm:"docker-containerd~1.6.21~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-github-mrunalp-fileutils", rpm:"golang-github-mrunalp-fileutils~0.5.0~2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-github-mrunalp-fileutils-devel", rpm:"golang-github-mrunalp-fileutils-devel~0.5.0~2.mga8", rls:"MAGEIA8"))) {
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
