# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.885063");
  script_version("2024-01-22T05:07:31+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2023-44487");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2024-01-22 05:07:31 +0000 (Mon, 22 Jan 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-10-14 01:15:00 +0000 (Sat, 14 Oct 2023)");
  script_tag(name:"creation_date", value:"2023-10-25 01:17:11 +0000 (Wed, 25 Oct 2023)");
  script_name("Fedora: Security Advisory for folly (FEDORA-2023-17efd3f2cd)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC38");

  script_xref(name:"Advisory-ID", value:"FEDORA-2023-17efd3f2cd");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/DWYNOYJJQQNS3T4CL3X3RJK4R4F7WB46");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'folly'
  package(s) announced via the FEDORA-2023-17efd3f2cd advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Folly (acronymed loosely after Facebook Open Source Library) is a library of
C++14 components designed with practicality and efficiency in mind. Folly
contains a variety of core library components used extensively at Facebook. In
particular, it&#39, s often a dependency of Facebook&#39, s other open source C++ efforts
and place where those projects can share code.

It complements (as opposed to competing against) offerings such as Boost and of
course std. In fact, we embark on defining our own component only when something
we need is either not available, or does not meet the needed performance
profile. We endeavor to remove things from folly if or when std or Boost
obsoletes them.

Performance concerns permeate much of Folly, sometimes leading to designs that
are more idiosyncratic than they would otherwise be (see e.g. PackedSyncPtr.h,
SmallLocks.h). Good performance at large scale is a unifying theme in all of
Folly.");

  script_tag(name:"affected", value:"'folly' package(s) on Fedora 38.");

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

  if(!isnull(res = isrpmvuln(pkg:"folly", rpm:"folly~2023.10.16.00~1.fc38", rls:"FC38"))) {
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