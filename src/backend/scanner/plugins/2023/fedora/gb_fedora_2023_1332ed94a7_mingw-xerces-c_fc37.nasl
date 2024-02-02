# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.885049");
  script_version("2023-10-27T16:11:33+0000");
  script_cve_id("CVE-2023-37536");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-10-27 16:11:33 +0000 (Fri, 27 Oct 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-10-18 20:00:00 +0000 (Wed, 18 Oct 2023)");
  script_tag(name:"creation_date", value:"2023-10-24 01:13:57 +0000 (Tue, 24 Oct 2023)");
  script_name("Fedora: Security Advisory for mingw-xerces-c (FEDORA-2023-1332ed94a7)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC37");

  script_xref(name:"Advisory-ID", value:"FEDORA-2023-1332ed94a7");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/DAOSSJ72CUJ535VRWTCVQKUYT2LYR3OM");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mingw-xerces-c'
  package(s) announced via the FEDORA-2023-1332ed94a7 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Xerces-C is a validating XML parser written in a portable subset of
C++. Xerces-C makes it easy to give your application the ability to
read and write XML data. A shared library is provided for parsing,
generating, manipulating, and validating XML documents. Xerces-C is
faithful to the XML 1.0 recommendation and associated standards (DOM
1.0, DOM 2.0. SAX 1.0, SAX 2.0, Namespaces).");

  script_tag(name:"affected", value:"'mingw-xerces-c' package(s) on Fedora 37.");

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

if(release == "FC37") {

  if(!isnull(res = isrpmvuln(pkg:"mingw-xerces-c", rpm:"mingw-xerces-c~3.2.4~1.fc37", rls:"FC37"))) {
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