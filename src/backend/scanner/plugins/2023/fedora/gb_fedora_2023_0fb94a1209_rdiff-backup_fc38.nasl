# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.885472");
  script_version("2023-12-29T16:09:56+0000");
  script_cve_id("CVE-2023-49797");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-12-29 16:09:56 +0000 (Fri, 29 Dec 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-12-12 22:23:00 +0000 (Tue, 12 Dec 2023)");
  script_tag(name:"creation_date", value:"2023-12-20 02:18:33 +0000 (Wed, 20 Dec 2023)");
  script_name("Fedora: Security Advisory for rdiff-backup (FEDORA-2023-0fb94a1209)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC38");

  script_xref(name:"Advisory-ID", value:"FEDORA-2023-0fb94a1209");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/2K2XIQLEMZIKUQUOWNDYWTEWYQTKMAN7");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'rdiff-backup'
  package(s) announced via the FEDORA-2023-0fb94a1209 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"rdiff-backup is a script, written in Python, that backs up one
directory to another and is intended to be run periodically (nightly
from cron for instance). The target directory ends up a copy of the
source directory, but extra reverse diffs are stored in the target
directory, so you can still recover files lost some time ago. The idea
is to combine the best features of a mirror and an incremental
backup. rdiff-backup can also operate in a bandwidth efficient manner
over a pipe, like rsync. Thus you can use rdiff-backup and ssh to
securely back a hard drive up to a remote location, and only the
differences from the previous backup will be transmitted.");

  script_tag(name:"affected", value:"'rdiff-backup' package(s) on Fedora 38.");

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

  if(!isnull(res = isrpmvuln(pkg:"rdiff-backup", rpm:"rdiff-backup~2.2.6~3.fc38", rls:"FC38"))) {
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