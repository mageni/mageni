# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2023.0303");
  script_cve_id("CVE-2023-3341", "CVE-2023-4236");
  script_tag(name:"creation_date", value:"2023-10-30 04:12:08 +0000 (Mon, 30 Oct 2023)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-09-20 13:15:12 +0000 (Wed, 20 Sep 2023)");

  script_name("Mageia: Security Advisory (MGASA-2023-0303)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2023-0303");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2023-0303.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=32039");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6390-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'bind' package(s) announced via the MGASA-2023-0303 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The code that processes control channel messages sent to `named` calls
certain functions recursively during packet parsing. Recursion depth is
only limited by the maximum accepted packet size, depending on the
environment, this may cause the packet-parsing code to run out of
available stack memory, causing `named` to terminate unexpectedly. Since
each incoming control channel message is fully parsed before its
contents are authenticated, exploiting this flaw does not require the
attacker to hold a valid RNDC key, only network access to the control
channel's configured TCP port is necessary. (CVE-2023-3341)

A flaw in the networking code handling DNS-over-TLS queries may cause
`named` to terminate unexpectedly due to an assertion failure. This
happens when internal data structures are incorrectly reused under
significant DNS-over-TLS query load. (CVE-2023-4236)");

  script_tag(name:"affected", value:"'bind' package(s) on Mageia 9.");

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

  if(!isnull(res = isrpmvuln(pkg:"bind", rpm:"bind~9.18.15~2.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-chroot", rpm:"bind-chroot~9.18.15~2.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-devel", rpm:"bind-devel~9.18.15~2.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-dlz-filesystem", rpm:"bind-dlz-filesystem~9.18.15~2.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-dlz-ldap", rpm:"bind-dlz-ldap~9.18.15~2.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-dlz-mysql", rpm:"bind-dlz-mysql~9.18.15~2.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-dlz-sqlite3", rpm:"bind-dlz-sqlite3~9.18.15~2.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-dnssec-utils", rpm:"bind-dnssec-utils~9.18.15~2.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-utils", rpm:"bind-utils~9.18.15~2.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64bind9.18.15", rpm:"lib64bind9.18.15~9.18.15~2.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbind9.18.15", rpm:"libbind9.18.15~9.18.15~2.2.mga9", rls:"MAGEIA9"))) {
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
