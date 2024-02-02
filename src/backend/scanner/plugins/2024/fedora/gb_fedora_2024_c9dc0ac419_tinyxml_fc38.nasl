# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.885543");
  script_version("2024-01-24T14:38:46+0000");
  script_cve_id("CVE-2021-42260", "CVE-2023-34194", "CVE-2023-40462");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2024-01-24 14:38:46 +0000 (Wed, 24 Jan 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-12-08 15:46:00 +0000 (Fri, 08 Dec 2023)");
  script_tag(name:"creation_date", value:"2024-01-18 09:13:51 +0000 (Thu, 18 Jan 2024)");
  script_name("Fedora: Security Advisory for tinyxml (FEDORA-2024-c9dc0ac419)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC38");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-c9dc0ac419");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/HOMBSHRIW5Q34SQSXYURYAOYDZD2NQF6");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'tinyxml'
  package(s) announced via the FEDORA-2024-c9dc0ac419 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"TinyXML is a simple, small, C++ XML parser that can be easily integrating
into other programs. Have you ever found yourself writing a text file parser
every time you needed to save human readable data or serialize objects?
TinyXML solves the text I/O file once and for all.
(Or, as a friend said, ends the Just Another Text File Parser problem.)");

  script_tag(name:"affected", value:"'tinyxml' package(s) on Fedora 38.");

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

  if(!isnull(res = isrpmvuln(pkg:"tinyxml", rpm:"tinyxml~2.6.2~28.fc38", rls:"FC38"))) {
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