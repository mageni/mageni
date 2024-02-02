# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.885443");
  script_version("2023-12-15T16:10:08+0000");
  script_cve_id("CVE-2023-6185", "CVE-2023-6186");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-12-15 16:10:08 +0000 (Fri, 15 Dec 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-12-14 14:41:00 +0000 (Thu, 14 Dec 2023)");
  script_tag(name:"creation_date", value:"2023-12-13 02:21:11 +0000 (Wed, 13 Dec 2023)");
  script_name("Fedora: Security Advisory for libreoffice (FEDORA-2023-0d971cd6aa)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC38");

  script_xref(name:"Advisory-ID", value:"FEDORA-2023-0d971cd6aa");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/HOF6LGTG2FGCDRK7SYOGPNLVGCEFBTEX");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libreoffice'
  package(s) announced via the FEDORA-2023-0d971cd6aa advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"LibreOffice is an Open Source, community-developed, office productivity suite.
It includes the key desktop applications, such as a word processor,
spreadsheet, presentation manager, formula editor and drawing program, with a
user interface and feature set similar to other office suites.  Sophisticated
and flexible, LibreOffice also works transparently with a variety of file
formats, including Microsoft Office File Formats.");

  script_tag(name:"affected", value:"'libreoffice' package(s) on Fedora 38.");

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

  if(!isnull(res = isrpmvuln(pkg:"libreoffice", rpm:"libreoffice~7.5.9.2~1.fc38", rls:"FC38"))) {
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