# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2023.0297");
  script_cve_id("CVE-2023-43782", "CVE-2023-43783");
  script_tag(name:"creation_date", value:"2023-10-23 04:11:50 +0000 (Mon, 23 Oct 2023)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:C/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-09-25 18:07:32 +0000 (Mon, 25 Sep 2023)");

  script_name("Mageia: Security Advisory (MGASA-2023-0297)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA(8|9)");

  script_xref(name:"Advisory-ID", value:"MGASA-2023-0297");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2023-0297.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=32361");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2023/10/05/4");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'cadence' package(s) announced via the MGASA-2023-0297 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Cadence through 0.9.2 2023-08-21 uses an Insecure
/tmp/.cadence-aloop-daemon.x Temporary File. The file is used even if it
has been created by a local adversary before Cadence started. The
adversary can then delete the file, disrupting Cadence. (CVE-2023-43782)

Cadence through 0.9.2 2023-08-21 uses an Insecure
/tmp/cadence-wineasio.reg Temporary File. The filename is used even if
it has been created by a local adversary before Cadence started. The
adversary can leverage this to create or overwrite files via a symlink
attack. In some kernel configurations, code injection into the Wine
registry is possible. (CVE-2023-43783)");

  script_tag(name:"affected", value:"'cadence' package(s) on Mageia 8, Mageia 9.");

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

  if(!isnull(res = isrpmvuln(pkg:"cadence", rpm:"cadence~0.9.1~3.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cadence-data", rpm:"cadence-data~0.9.1~3.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cadence-tools", rpm:"cadence-tools~0.9.1~3.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"catarina", rpm:"catarina~0.9.1~3.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"catia", rpm:"catia~0.9.1~3.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"claudia", rpm:"claudia~0.9.1~3.1.mga8", rls:"MAGEIA8"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"cadence", rpm:"cadence~0.9.1~7.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cadence-data", rpm:"cadence-data~0.9.1~7.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cadence-tools", rpm:"cadence-tools~0.9.1~7.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"catarina", rpm:"catarina~0.9.1~7.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"catia", rpm:"catia~0.9.1~7.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"claudia", rpm:"claudia~0.9.1~7.1.mga9", rls:"MAGEIA9"))) {
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
