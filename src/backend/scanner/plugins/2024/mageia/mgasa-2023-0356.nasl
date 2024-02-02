# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2023.0356");
  script_cve_id("CVE-2023-48795");
  script_tag(name:"creation_date", value:"2024-01-01 04:12:31 +0000 (Mon, 01 Jan 2024)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:C/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-12-28 18:26:44 +0000 (Thu, 28 Dec 2023)");

  script_name("Mageia: Security Advisory (MGASA-2023-0356)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2023-0356");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2023-0356.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=32644");
  script_xref(name:"URL", value:"https://github.com/proftpd/proftpd/blob/1.3.8/RELEASE_NOTES");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'proftpd' package(s) announced via the MGASA-2023-0356 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"ProFTPd upstream has released version 1.3.8b to fix CVE-2023-48795.
From the changelog:
- Implemented mitigations for 'Terrapin' SSH attack (CVE-2023-48795).");

  script_tag(name:"affected", value:"'proftpd' package(s) on Mageia 9.");

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

  if(!isnull(res = isrpmvuln(pkg:"proftpd", rpm:"proftpd~1.3.8b~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"proftpd-devel", rpm:"proftpd-devel~1.3.8b~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"proftpd-mod_autohost", rpm:"proftpd-mod_autohost~1.3.8b~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"proftpd-mod_ban", rpm:"proftpd-mod_ban~1.3.8b~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"proftpd-mod_case", rpm:"proftpd-mod_case~1.3.8b~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"proftpd-mod_ctrls_admin", rpm:"proftpd-mod_ctrls_admin~1.3.8b~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"proftpd-mod_ifsession", rpm:"proftpd-mod_ifsession~1.3.8b~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"proftpd-mod_ldap", rpm:"proftpd-mod_ldap~1.3.8b~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"proftpd-mod_load", rpm:"proftpd-mod_load~1.3.8b~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"proftpd-mod_memcache", rpm:"proftpd-mod_memcache~1.3.8b~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"proftpd-mod_quotatab", rpm:"proftpd-mod_quotatab~1.3.8b~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"proftpd-mod_quotatab_file", rpm:"proftpd-mod_quotatab_file~1.3.8b~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"proftpd-mod_quotatab_ldap", rpm:"proftpd-mod_quotatab_ldap~1.3.8b~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"proftpd-mod_quotatab_radius", rpm:"proftpd-mod_quotatab_radius~1.3.8b~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"proftpd-mod_quotatab_sql", rpm:"proftpd-mod_quotatab_sql~1.3.8b~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"proftpd-mod_radius", rpm:"proftpd-mod_radius~1.3.8b~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"proftpd-mod_ratio", rpm:"proftpd-mod_ratio~1.3.8b~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"proftpd-mod_rewrite", rpm:"proftpd-mod_rewrite~1.3.8b~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"proftpd-mod_sftp", rpm:"proftpd-mod_sftp~1.3.8b~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"proftpd-mod_sftp_pam", rpm:"proftpd-mod_sftp_pam~1.3.8b~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"proftpd-mod_sftp_sql", rpm:"proftpd-mod_sftp_sql~1.3.8b~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"proftpd-mod_shaper", rpm:"proftpd-mod_shaper~1.3.8b~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"proftpd-mod_site_misc", rpm:"proftpd-mod_site_misc~1.3.8b~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"proftpd-mod_sql", rpm:"proftpd-mod_sql~1.3.8b~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"proftpd-mod_sql_mysql", rpm:"proftpd-mod_sql_mysql~1.3.8b~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"proftpd-mod_sql_passwd", rpm:"proftpd-mod_sql_passwd~1.3.8b~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"proftpd-mod_sql_postgres", rpm:"proftpd-mod_sql_postgres~1.3.8b~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"proftpd-mod_sql_sqlite", rpm:"proftpd-mod_sql_sqlite~1.3.8b~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"proftpd-mod_tls", rpm:"proftpd-mod_tls~1.3.8b~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"proftpd-mod_tls_memcache", rpm:"proftpd-mod_tls_memcache~1.3.8b~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"proftpd-mod_tls_shmcache", rpm:"proftpd-mod_tls_shmcache~1.3.8b~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"proftpd-mod_unique_id", rpm:"proftpd-mod_unique_id~1.3.8b~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"proftpd-mod_vroot", rpm:"proftpd-mod_vroot~1.3.8b~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"proftpd-mod_wrap", rpm:"proftpd-mod_wrap~1.3.8b~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"proftpd-mod_wrap_file", rpm:"proftpd-mod_wrap_file~1.3.8b~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"proftpd-mod_wrap_sql", rpm:"proftpd-mod_wrap_sql~1.3.8b~1.mga9", rls:"MAGEIA9"))) {
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
