# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.885280");
  script_version("2023-12-07T05:05:41+0000");
  script_cve_id("CVE-2023-39325");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2023-12-07 05:05:41 +0000 (Thu, 07 Dec 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-10-31 18:05:00 +0000 (Tue, 31 Oct 2023)");
  script_tag(name:"creation_date", value:"2023-11-19 02:16:38 +0000 (Sun, 19 Nov 2023)");
  script_name("Fedora: Security Advisory for syncthing (FEDORA-2023-d58c8eeb7c)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC38");

  script_xref(name:"Advisory-ID", value:"FEDORA-2023-d58c8eeb7c");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/QF5QSYAOPDOWLY6DUHID56Q4HQFYB45I");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'syncthing'
  package(s) announced via the FEDORA-2023-d58c8eeb7c advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Syncthing replaces other file synchronization services with something
open, trustworthy and decentralized. Your data is your data alone and
you deserve to choose where it is stored, if it is shared with some
third party and how it&#39, s transmitted over the Internet. Using syncthing,
that control is returned to you.

This package contains the syncthing client binary and systemd services.");

  script_tag(name:"affected", value:"'syncthing' package(s) on Fedora 38.");

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

  if(!isnull(res = isrpmvuln(pkg:"syncthing", rpm:"syncthing~1.26.0~1.fc38", rls:"FC38"))) {
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