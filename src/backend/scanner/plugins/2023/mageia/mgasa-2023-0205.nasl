# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2023.0205");
  script_cve_id("CVE-2023-2602", "CVE-2023-2603");
  script_tag(name:"creation_date", value:"2023-06-29 04:13:13 +0000 (Thu, 29 Jun 2023)");
  script_version("2023-06-29T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-06-29 05:05:23 +0000 (Thu, 29 Jun 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-06-21 19:02:00 +0000 (Wed, 21 Jun 2023)");

  script_name("Mageia: Security Advisory (MGASA-2023-0205)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2023-0205");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2023-0205.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=31938");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2023/05/15/4");
  script_xref(name:"URL", value:"https://sites.google.com/site/fullycapable/release-notes-for-libcap#h.iuvg7sbjg8pe");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2023/05/16/2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6166-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libcap' package(s) announced via the MGASA-2023-0205 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A vulnerability was found in the pthread_create() function in libcap. This
issue may allow a malicious actor to use cause __real_pthread_create() to
return an error, which can exhaust the process memory. (CVE-2023-2602)

A vulnerability was found in libcap. This issue occurs in the _libcap_strdup()
function and can lead to an integer overflow if the input string is close
to 4GiB. (CVE-2023-2603)");

  script_tag(name:"affected", value:"'libcap' package(s) on Mageia 8.");

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

  if(!isnull(res = isrpmvuln(pkg:"lib64cap-devel", rpm:"lib64cap-devel~2.46~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64cap2", rpm:"lib64cap2~2.46~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcap", rpm:"libcap~2.46~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcap-devel", rpm:"libcap-devel~2.46~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcap-utils", rpm:"libcap-utils~2.46~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcap2", rpm:"libcap2~2.46~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pam_cap", rpm:"pam_cap~2.46~1.1.mga8", rls:"MAGEIA8"))) {
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
