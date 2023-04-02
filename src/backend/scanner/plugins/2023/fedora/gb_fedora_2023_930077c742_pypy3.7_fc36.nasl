# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.827342");
  script_version("2023-03-23T10:09:48+0000");
  script_cve_id("CVE-2022-37454");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-03-23 10:09:48 +0000 (Thu, 23 Mar 2023)");
  script_tag(name:"creation_date", value:"2023-03-19 02:03:44 +0000 (Sun, 19 Mar 2023)");
  script_name("Fedora: Security Advisory for pypy3.7 (FEDORA-2023-930077c742)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC36");

  script_xref(name:"Advisory-ID", value:"FEDORA-2023-930077c742");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/EIWYWZ6C3TWMCTZEAWREYXQB3WTNZXZE");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'pypy3.7'
  package(s) announced via the FEDORA-2023-930077c742 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"PyPy&#39, s implementation of Python 3.7, featuring a Just-In-Time compiler
on some CPU architectures, and various optimized implementations
of the standard types (strings, dictionaries, etc.).


This build of PyPy has JIT-compilation enabled.");

  script_tag(name:"affected", value:"'pypy3.7' package(s) on Fedora 36.");

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

if(release == "FC36") {

  if(!isnull(res = isrpmvuln(pkg:"pypy3.7", rpm:"pypy3.7~7.3.9~5.3.7.fc36", rls:"FC36"))) {
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
