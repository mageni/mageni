# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.885226");
  script_version("2023-12-06T05:06:11+0000");
  # TODO: No CVE assigned yet.
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-12-06 05:06:11 +0000 (Wed, 06 Dec 2023)");
  script_tag(name:"creation_date", value:"2023-11-08 02:14:46 +0000 (Wed, 08 Nov 2023)");
  script_name("Fedora: Security Advisory for mlpack (FEDORA-2023-23c0bd9a45)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC38");

  script_xref(name:"Advisory-ID", value:"FEDORA-2023-23c0bd9a45");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/NFSKBBQOYROUMCTMWZ2T6U7OSEHX2I3Y");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mlpack'
  package(s) announced via the FEDORA-2023-23c0bd9a45 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"mlpack is a C++ machine learning library with emphasis on scalability, speed,
and ease-of-use. Its aim is to make machine learning possible for novice users
by means of a simple, consistent API, while simultaneously exploiting C++
language features to provide maximum performance and maximum flexibility for
expert users. mlpack outperforms competing machine learning libraries by large
margins.");

  script_tag(name:"affected", value:"'mlpack' package(s) on Fedora 38.");

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

  if(!isnull(res = isrpmvuln(pkg:"mlpack", rpm:"mlpack~4.2.1~5.fc38", rls:"FC38"))) {
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