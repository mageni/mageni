# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.885634");
  script_version("2024-02-02T14:37:52+0000");
  script_cve_id("CVE-2023-29491", "CVE-2023-50495");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:52 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-04-24 13:23:52 +0000 (Mon, 24 Apr 2023)");
  script_tag(name:"creation_date", value:"2024-01-31 02:02:08 +0000 (Wed, 31 Jan 2024)");
  script_name("Fedora: Security Advisory for ncurses (FEDORA-2024-96090dafaf)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC38");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-96090dafaf");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/LU4MYMKFEZQ5VSCVLRIZGDQOUW3T44GT");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ncurses'
  package(s) announced via the FEDORA-2024-96090dafaf advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The curses library routines are a terminal-independent method of
updating character screens with reasonable optimization.  The ncurses
(new curses) library is a freely distributable replacement for the
discontinued 4.4 BSD classic curses library.

This package contains support utilities, including a terminfo compiler
tic, a decompiler infocmp, clear, tput, tset, and a termcap conversion
tool captoinfo.");

  script_tag(name:"affected", value:"'ncurses' package(s) on Fedora 38.");

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

if(release == "FC38") {

  if(!isnull(res = isrpmvuln(pkg:"ncurses", rpm:"ncurses~6.4~7.20230520.fc38", rls:"FC38"))) {
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