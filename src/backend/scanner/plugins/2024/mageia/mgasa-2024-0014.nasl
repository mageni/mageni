# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2024.0014");
  script_cve_id("CVE-2023-34194");
  script_tag(name:"creation_date", value:"2024-01-18 04:11:52 +0000 (Thu, 18 Jan 2024)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-12-18 18:31:41 +0000 (Mon, 18 Dec 2023)");

  script_name("Mageia: Security Advisory (MGASA-2024-0014)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2024-0014");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2024-0014.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=32703");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/4QCR5PIOBGDIDS6SYRESTMDJSEDFSCOE/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'tinyxml' package(s) announced via the MGASA-2024-0014 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The updated packages fix a security vulnerability:
StringEqual in TiXmlDeclaration::Parse in tinyxmlparser.cpp in TinyXML
through 2.6.2 has a reachable assertion (and application exit) via a
crafted XML document with a '\0' located after whitespace.
(CVE-2023-34194)");

  script_tag(name:"affected", value:"'tinyxml' package(s) on Mageia 9.");

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

if(release == "MAGEIA9") {

  if(!isnull(res = isrpmvuln(pkg:"lib64tinyxml-devel", rpm:"lib64tinyxml-devel~2.6.2~14.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64tinyxml0", rpm:"lib64tinyxml0~2.6.2~14.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtinyxml-devel", rpm:"libtinyxml-devel~2.6.2~14.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtinyxml0", rpm:"libtinyxml0~2.6.2~14.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tinyxml", rpm:"tinyxml~2.6.2~14.1.mga9", rls:"MAGEIA9"))) {
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
