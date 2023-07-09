# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2023.0204");
  script_cve_id("CVE-2020-36649", "CVE-2022-47927", "CVE-2023-22909", "CVE-2023-2291", "CVE-2023-29141");
  script_tag(name:"creation_date", value:"2023-06-29 04:13:13 +0000 (Thu, 29 Jun 2023)");
  script_version("2023-06-29T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-06-29 05:05:23 +0000 (Thu, 29 Jun 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-04-11 06:24:00 +0000 (Tue, 11 Apr 2023)");

  script_name("Mageia: Security Advisory (MGASA-2023-0204)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2023-0204");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2023-0204.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=31463");
  script_xref(name:"URL", value:"https://lists.wikimedia.org/hyperkitty/list/mediawiki-announce@lists.wikimedia.org/message/UEMW64LVEH3BEXCJV43CVS6XPYURKWU3/");
  script_xref(name:"URL", value:"https://lists.wikimedia.org/hyperkitty/list/mediawiki-announce@lists.wikimedia.org/message/6UQBHI5FWLATD7QO7DI4YS54U7XSSLAN/");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/AP65YEN762IBNQPOYGUVLTQIDLM5XD2A/");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/ZGK4NZPIJ5ET2ANRZOUYPCRIB5I64JR7/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mediawiki' package(s) announced via the MGASA-2023-0204 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Bundled PapaParse copy in VisualEditor has known ReDos (CVE-2020-36649).

An issue was discovered in MediaWiki before 1.35.9. When installing with a
pre-existing data directory that has weak permissions, the SQLite files
are created with file mode 0644, i.e., world readable to local users.
These files include credentials data (CVE-2022-47927).

An issue was discovered in MediaWiki before 1.35.9. SpecialMobileHistory
allows remote attackers to cause a denial of service because database
queries are slow (CVE-2023-22909).

An issue was discovered in MediaWiki before 1.35.9. E-Widgets does widget
replacement in HTML attributes, which can lead to XSS, because widget
authors often do not expect that their widget is executed in an HTML
attribute context (CVE-2023-22911).

An issue was discovered in MediaWiki before 1.35.10. An auto-block can
occur for an untrusted X-Forwarded-For header (CVE-2023-29141).

OATHAuth allows replay attacks when MediaWiki is configured without
ObjectCache, Insecure Default Configuration (T330086).");

  script_tag(name:"affected", value:"'mediawiki' package(s) on Mageia 8.");

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

if(release == "MAGEIA8") {

  if(!isnull(res = isrpmvuln(pkg:"mediawiki", rpm:"mediawiki~1.35.10~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mediawiki-mysql", rpm:"mediawiki-mysql~1.35.10~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mediawiki-pgsql", rpm:"mediawiki-pgsql~1.35.10~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mediawiki-sqlite", rpm:"mediawiki-sqlite~1.35.10~1.mga8", rls:"MAGEIA8"))) {
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
