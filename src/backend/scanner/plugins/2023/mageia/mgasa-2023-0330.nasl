# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2023.0330");
  script_cve_id("CVE-2023-36053");
  script_tag(name:"creation_date", value:"2023-11-30 04:12:11 +0000 (Thu, 30 Nov 2023)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-07-11 14:26:13 +0000 (Tue, 11 Jul 2023)");

  script_name("Mageia: Security Advisory (MGASA-2023-0330)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA(8|9)");

  script_xref(name:"Advisory-ID", value:"MGASA-2023-0330");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2023-0330.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=32069");
  script_xref(name:"URL", value:"https://www.djangoproject.com/weblog/2023/jul/03/security-releases/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python-django' package(s) announced via the MGASA-2023-0330 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that python-django EmailValidator and URLValidator
were subject to potential regular expression denial of service attack
via a very large number of domain name labels of emails and URLs
(CVE-2023-36053).");

  script_tag(name:"affected", value:"'python-django' package(s) on Mageia 8, Mageia 9.");

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

  if(!isnull(res = isrpmvuln(pkg:"python-django", rpm:"python-django~3.2.23~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-django", rpm:"python3-django~3.2.23~1.mga8", rls:"MAGEIA8"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"python-django", rpm:"python-django~4.1.13~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-django", rpm:"python3-django~4.1.13~1.mga9", rls:"MAGEIA9"))) {
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
