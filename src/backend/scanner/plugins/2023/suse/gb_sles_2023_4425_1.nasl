# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2023.4425.1");
  script_cve_id("CVE-2023-5868", "CVE-2023-5869", "CVE-2023-5870");
  script_tag(name:"creation_date", value:"2023-11-14 04:25:56 +0000 (Tue, 14 Nov 2023)");
  script_version("2024-02-02T14:37:52+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:52 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-12-10 18:15:07 +0000 (Sun, 10 Dec 2023)");

  script_name("SUSE: Security Advisory (SUSE-SU-2023:4425-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:4425-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2023/suse-su-20234425-1/");
  script_xref(name:"URL", value:"https://www.postgresql.org/about/news/2715");
  script_xref(name:"URL", value:"https://www.postgresql.org/docs/16/release-16.html");
  script_xref(name:"URL", value:"https://www.postgresql.org/docs/16/release-16-1.html");
  script_xref(name:"URL", value:"https://www.postgresql.org/docs/15/release-15-5.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'postgresql, postgresql15, postgresql16' package(s) announced via the SUSE-SU-2023:4425-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for postgresql, postgresql15, postgresql16 fixes the following issues:
This update ships postgresql 16 (jsc#PED-5586).
Security issues fixed:

CVE-2023-5868: Fix handling of unknown-type
 arguments in DISTINCT 'any' aggregate functions. This error led
 to a text-type value being interpreted as an unknown-type value
 (that is, a zero-terminated string) at runtime. This could
 result in disclosure of server memory following the text value. (bsc#1216962)
CVE-2023-5869: Detect integer overflow while
 computing new array dimensions. When assigning new elements to
 array subscripts that are outside the current array bounds, an
 undetected integer overflow could occur in edge cases. Memory
 stomps that are potentially exploitable for arbitrary code
 execution are possible, and so is disclosure of server memory. (bsc#1216961)
CVE-2023-5870: Prevent the pg_signal_backend role
 from signalling background workers and autovacuum processes.
 The documentation says that pg_signal_backend cannot issue
 signals to superuser-owned processes. It was able to signal
 these background processes, though, because they advertise a
 role OID of zero. Treat that as indicating superuser ownership.
 The security implications of cancelling one of these process
 types are fairly small so far as the core code goes (we'll just
 start another one), but extensions might add background workers
 that are more vulnerable.
 Also ensure that the is_superuser parameter is set correctly in
 such processes. No specific security consequences are known for
 that oversight, but it might be significant for some extensions.
 (bsc#1216960)

Changes in postgresql16:


Upgrade to 16.1:


[link moved to references]

[link moved to references] [link moved to references]

Changes in postgresql15:


Update to 15.5 [link moved to references]


The libs and mini package are now provided by postgresql16.

Overhaul postgresql-README.SUSE and move it from the binary
 package to the noarch wrapper package.
Change the unix domain socket location from /var/run to /run.

Changes in postgresql:

Bump default to 16.
Interlock version and release of all noarch packages except for
 the postgresql-docs.
Bump major version to prepare for PostgreSQL 16, but keep
 default at 15 for now on Factory.
bsc#1122892: Add a sysconfig variable for initdb.
Overhaul postgresql-README.SUSE and move it from the binary
 package to the noarch wrapper package.
bsc#1179231: Add an explanation for the /tmp -> /run/postgresql
 move and permission change.
Add postgresql-README as a separate source file.
bsc#1209208: Drop hard dependency on systemd bsc#1206796: Refine the distinction of where to use sysusers and
 use bcond to have the expression only in one place.
avoid bashisms in /bin/sh based startup script
Bump to postgresql 15
Change to systemd-sysusers");

  script_tag(name:"affected", value:"'postgresql, postgresql15, postgresql16' package(s) on SUSE Linux Enterprise High Performance Computing 12-SP5, SUSE Linux Enterprise Server 12-SP5, SUSE Linux Enterprise Server for SAP Applications 12-SP5, SUSE Linux Enterprise Software Development Kit 12-SP5.");

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

if(release == "SLES12.0SP5") {

  if(!isnull(res = isrpmvuln(pkg:"libecpg6", rpm:"libecpg6~16.1~3.7.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libecpg6-32bit", rpm:"libecpg6-32bit~16.1~3.7.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libecpg6-debuginfo", rpm:"libecpg6-debuginfo~16.1~3.7.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libecpg6-debuginfo-32bit", rpm:"libecpg6-debuginfo-32bit~16.1~3.7.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpq5", rpm:"libpq5~16.1~3.7.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpq5-32bit", rpm:"libpq5-32bit~16.1~3.7.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpq5-debuginfo", rpm:"libpq5-debuginfo~16.1~3.7.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpq5-debuginfo-32bit", rpm:"libpq5-debuginfo-32bit~16.1~3.7.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql", rpm:"postgresql~16~4.23.3", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql-contrib", rpm:"postgresql-contrib~16~4.23.3", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql-docs", rpm:"postgresql-docs~16~4.23.3", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql-plperl", rpm:"postgresql-plperl~16~4.23.3", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql-plpython", rpm:"postgresql-plpython~16~4.23.3", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql-pltcl", rpm:"postgresql-pltcl~16~4.23.3", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql-server", rpm:"postgresql-server~16~4.23.3", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql15", rpm:"postgresql15~15.5~3.19.2", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql15-contrib", rpm:"postgresql15-contrib~15.5~3.19.2", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql15-contrib-debuginfo", rpm:"postgresql15-contrib-debuginfo~15.5~3.19.2", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql15-debuginfo", rpm:"postgresql15-debuginfo~15.5~3.19.2", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql15-debugsource", rpm:"postgresql15-debugsource~15.5~3.19.2", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql15-docs", rpm:"postgresql15-docs~15.5~3.19.2", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql15-plperl", rpm:"postgresql15-plperl~15.5~3.19.2", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql15-plperl-debuginfo", rpm:"postgresql15-plperl-debuginfo~15.5~3.19.2", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql15-plpython", rpm:"postgresql15-plpython~15.5~3.19.2", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql15-plpython-debuginfo", rpm:"postgresql15-plpython-debuginfo~15.5~3.19.2", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql15-pltcl", rpm:"postgresql15-pltcl~15.5~3.19.2", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql15-pltcl-debuginfo", rpm:"postgresql15-pltcl-debuginfo~15.5~3.19.2", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql15-server", rpm:"postgresql15-server~15.5~3.19.2", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql15-server-debuginfo", rpm:"postgresql15-server-debuginfo~15.5~3.19.2", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql16", rpm:"postgresql16~16.1~3.7.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql16-contrib", rpm:"postgresql16-contrib~16.1~3.7.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql16-contrib-debuginfo", rpm:"postgresql16-contrib-debuginfo~16.1~3.7.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql16-debuginfo", rpm:"postgresql16-debuginfo~16.1~3.7.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql16-debugsource", rpm:"postgresql16-debugsource~16.1~3.7.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql16-docs", rpm:"postgresql16-docs~16.1~3.7.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql16-plperl", rpm:"postgresql16-plperl~16.1~3.7.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql16-plperl-debuginfo", rpm:"postgresql16-plperl-debuginfo~16.1~3.7.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql16-plpython", rpm:"postgresql16-plpython~16.1~3.7.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql16-plpython-debuginfo", rpm:"postgresql16-plpython-debuginfo~16.1~3.7.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql16-pltcl", rpm:"postgresql16-pltcl~16.1~3.7.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql16-pltcl-debuginfo", rpm:"postgresql16-pltcl-debuginfo~16.1~3.7.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql16-server", rpm:"postgresql16-server~16.1~3.7.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql16-server-debuginfo", rpm:"postgresql16-server-debuginfo~16.1~3.7.1", rls:"SLES12.0SP5"))) {
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
