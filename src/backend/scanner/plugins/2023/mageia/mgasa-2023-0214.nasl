# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2023.0214");
  script_tag(name:"creation_date", value:"2023-07-10 04:12:52 +0000 (Mon, 10 Jul 2023)");
  script_version("2023-07-10T08:07:42+0000");
  script_tag(name:"last_modification", value:"2023-07-10 08:07:42 +0000 (Mon, 10 Jul 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Mageia: Security Advisory (MGASA-2023-0214)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2023-0214");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2023-0214.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=30216");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/VRQ7IRKZITJLT44RH5PJICZIIRQJLXEE/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'perl-DBD-SQLite' package(s) announced via the MGASA-2023-0214 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Possible unfixed security issues due to bundled sqlite3");

  script_tag(name:"affected", value:"'perl-DBD-SQLite' package(s) on Mageia 8.");

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

  if(!isnull(res = isrpmvuln(pkg:"perl-DBD-SQLite", rpm:"perl-DBD-SQLite~1.660.0~1.1.mga8", rls:"MAGEIA8"))) {
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
