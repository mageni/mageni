# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2024.0009");
  script_cve_id("CVE-2023-6377", "CVE-2023-6478");
  script_tag(name:"creation_date", value:"2024-01-15 04:12:30 +0000 (Mon, 15 Jan 2024)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-12-13 07:15:30 +0000 (Wed, 13 Dec 2023)");

  script_name("Mageia: Security Advisory (MGASA-2024-0009)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2024-0009");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2024-0009.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=32625");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2023/12/13/1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6555-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'tigervnc, x11-server, x11-server-xwayland' package(s) announced via the MGASA-2024-0009 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The updated packages fix security vulnerabilities:
A flaw was found in xorg-server. Querying or changing XKB button actions
such as moving from a touchpad to a mouse can result in out-of-bounds
memory reads and writes. This may allow local privilege escalation or
possible remote code execution in cases where X11 forwarding is
involved. (CVE-2023-6377)
A flaw was found in xorg-server. A specially crafted request to
RRChangeProviderProperty or RRChangeOutputProperty can trigger an
integer overflow which may lead to a disclosure of sensitive
information. (CVE-2023-6478)");

  script_tag(name:"affected", value:"'tigervnc, x11-server, x11-server-xwayland' package(s) on Mageia 9.");

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

  if(!isnull(res = isrpmvuln(pkg:"tigervnc", rpm:"tigervnc~1.13.1~2.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tigervnc-java", rpm:"tigervnc-java~1.13.1~2.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tigervnc-server", rpm:"tigervnc-server~1.13.1~2.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tigervnc-server-module", rpm:"tigervnc-server-module~1.13.1~2.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"x11-server", rpm:"x11-server~21.1.8~7.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"x11-server-common", rpm:"x11-server-common~21.1.8~7.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"x11-server-devel", rpm:"x11-server-devel~21.1.8~7.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"x11-server-source", rpm:"x11-server-source~21.1.8~7.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"x11-server-xephyr", rpm:"x11-server-xephyr~21.1.8~7.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"x11-server-xnest", rpm:"x11-server-xnest~21.1.8~7.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"x11-server-xorg", rpm:"x11-server-xorg~21.1.8~7.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"x11-server-xvfb", rpm:"x11-server-xvfb~21.1.8~7.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"x11-server-xwayland", rpm:"x11-server-xwayland~22.1.9~1.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"x11-server-xwayland-devel", rpm:"x11-server-xwayland-devel~22.1.9~1.2.mga9", rls:"MAGEIA9"))) {
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
