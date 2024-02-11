# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2024.0026");
  script_cve_id("CVE-2023-6246", "CVE-2023-6779", "CVE-2023-6780");
  script_tag(name:"creation_date", value:"2024-02-05 04:11:46 +0000 (Mon, 05 Feb 2024)");
  script_version("2024-02-09T05:06:25+0000");
  script_tag(name:"last_modification", value:"2024-02-09 05:06:25 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-09 00:59:38 +0000 (Fri, 09 Feb 2024)");

  script_name("Mageia: Security Advisory (MGASA-2024-0026)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2024-0026");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2024-0026.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=32796");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-5611-1");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2024-aec80d6e8a");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'glibc' package(s) announced via the MGASA-2024-0026 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The updated packages fix security vulnerabilities:
A heap-based buffer overflow was found in the __vsyslog_internal
function of the glibc library. This function is called by the syslog and
vsyslog functions. This issue occurs when the openlog function was not
called, or called with the ident argument set to NULL, and the program
name (the basename of argv[0]) is bigger than 1024 bytes, resulting in
an application crash or local privilege escalation. (CVE-2023-6246)
An off-by-one heap-based buffer overflow was found in the
__vsyslog_internal function of the glibc library. This function is
called by the syslog and vsyslog functions. This issue occurs when these
functions are called with a message bigger than INT_MAX bytes, leading
to an incorrect calculation of the buffer size to store the message,
resulting in an application crash. (CVE-2023-6779)
An integer overflow was found in the __vsyslog_internal function of the
glibc library. This function is called by the syslog and vsyslog
functions. This issue occurs when these functions are called with a very
long message, leading to an incorrect calculation of the buffer size to
store the message, resulting in undefined behavior. (CVE-2023-6780)");

  script_tag(name:"affected", value:"'glibc' package(s) on Mageia 9.");

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

  if(!isnull(res = isrpmvuln(pkg:"glibc", rpm:"glibc~2.36~52.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-devel", rpm:"glibc-devel~2.36~52.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-doc", rpm:"glibc-doc~2.36~52.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-i18ndata", rpm:"glibc-i18ndata~2.36~52.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-profile", rpm:"glibc-profile~2.36~52.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-static-devel", rpm:"glibc-static-devel~2.36~52.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-utils", rpm:"glibc-utils~2.36~52.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nscd", rpm:"nscd~2.36~52.mga9", rls:"MAGEIA9"))) {
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
