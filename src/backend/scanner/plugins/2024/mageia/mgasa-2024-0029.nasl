# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2024.0029");
  script_cve_id("CVE-2023-51764");
  script_tag(name:"creation_date", value:"2024-02-09 04:12:12 +0000 (Fri, 09 Feb 2024)");
  script_version("2024-02-09T05:06:25+0000");
  script_tag(name:"last_modification", value:"2024-02-09 05:06:25 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-01-05 16:19:53 +0000 (Fri, 05 Jan 2024)");

  script_name("Mageia: Security Advisory (MGASA-2024-0029)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2024-0029");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2024-0029.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=32647");
  script_xref(name:"URL", value:"https://www.postfix.org/smtp-smuggling.html");
  script_xref(name:"URL", value:"https://sec-consult.com/blog/detail/smtp-smuggling-spoofing-e-mails-worldwide/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'postfix' package(s) announced via the MGASA-2024-0029 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Postfix has been updated to fix smtp smuggling, an email spoofing attack
that involves a composition of email services with specific differences
in the way they handle line endings other than <CR><LF>.");

  script_tag(name:"affected", value:"'postfix' package(s) on Mageia 9.");

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

  if(!isnull(res = isrpmvuln(pkg:"lib64postfix1", rpm:"lib64postfix1~3.8.4~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpostfix1", rpm:"libpostfix1~3.8.4~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postfix", rpm:"postfix~3.8.4~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postfix-cdb", rpm:"postfix-cdb~3.8.4~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postfix-ldap", rpm:"postfix-ldap~3.8.4~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postfix-mysql", rpm:"postfix-mysql~3.8.4~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postfix-pcre", rpm:"postfix-pcre~3.8.4~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postfix-pgsql", rpm:"postfix-pgsql~3.8.4~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postfix-sdbm", rpm:"postfix-sdbm~3.8.4~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postfix-sqlite", rpm:"postfix-sqlite~3.8.4~1.mga9", rls:"MAGEIA9"))) {
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
