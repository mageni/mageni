# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2024.0013");
  script_tag(name:"creation_date", value:"2024-01-17 04:11:51 +0000 (Wed, 17 Jan 2024)");
  script_version("2024-01-17T05:05:30+0000");
  script_tag(name:"last_modification", value:"2024-01-17 05:05:30 +0000 (Wed, 17 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Mageia: Security Advisory (MGASA-2024-0013)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2024-0013");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2024-0013.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=32701");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2023/11/17/1");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2024/01/04/1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'hplip' package(s) announced via the MGASA-2024-0013 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"There were security issues in hplip's `hpps` program due to fixed /tmp
path usage in prnt/hpps/hppsfilter.c
This update fixes these issues.");

  script_tag(name:"affected", value:"'hplip' package(s) on Mageia 9.");

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

  if(!isnull(res = isrpmvuln(pkg:"hplip", rpm:"hplip~3.22.10~4.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hplip-doc", rpm:"hplip-doc~3.22.10~4.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hplip-gui", rpm:"hplip-gui~3.22.10~4.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hplip-hpijs", rpm:"hplip-hpijs~3.22.10~4.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hplip-hpijs-ppds", rpm:"hplip-hpijs-ppds~3.22.10~4.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hplip-model-data", rpm:"hplip-model-data~3.22.10~4.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64hpip0", rpm:"lib64hpip0~3.22.10~4.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64hpip0-devel", rpm:"lib64hpip0-devel~3.22.10~4.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64sane-hpaio1", rpm:"lib64sane-hpaio1~3.22.10~4.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhpip0", rpm:"libhpip0~3.22.10~4.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhpip0-devel", rpm:"libhpip0-devel~3.22.10~4.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsane-hpaio1", rpm:"libsane-hpaio1~3.22.10~4.1.mga9", rls:"MAGEIA9"))) {
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
