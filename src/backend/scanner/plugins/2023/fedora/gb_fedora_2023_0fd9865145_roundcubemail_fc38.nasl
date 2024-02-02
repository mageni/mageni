# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.885265");
  script_version("2023-12-07T05:05:41+0000");
  script_cve_id("CVE-2023-47272");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"2023-12-07 05:05:41 +0000 (Thu, 07 Dec 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-11-15 05:15:00 +0000 (Wed, 15 Nov 2023)");
  script_tag(name:"creation_date", value:"2023-11-16 02:16:28 +0000 (Thu, 16 Nov 2023)");
  script_name("Fedora: Security Advisory for roundcubemail (FEDORA-2023-0fd9865145)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC38");

  script_xref(name:"Advisory-ID", value:"FEDORA-2023-0fd9865145");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/YFRGBPET73URF6364CI547ZVWQESJLGK");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'roundcubemail'
  package(s) announced via the FEDORA-2023-0fd9865145 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"RoundCube Webmail is a browser-based multilingual IMAP client
with an application-like user interface. It provides full
functionality you expect from an e-mail client, including MIME
support, address book, folder manipulation, message searching
and spell checking. RoundCube Webmail is written in PHP and
requires a database: MySQL, PostgreSQL and SQLite are known to
work. The user interface is fully skinnable using XHTML and
CSS 2.");

  script_tag(name:"affected", value:"'roundcubemail' package(s) on Fedora 38.");

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

  if(!isnull(res = isrpmvuln(pkg:"roundcubemail", rpm:"roundcubemail~1.6.5~1.fc38", rls:"FC38"))) {
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