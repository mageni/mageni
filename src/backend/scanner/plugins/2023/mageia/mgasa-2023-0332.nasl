# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2023.0332");
  script_cve_id("CVE-2023-47272", "CVE-2023-5631");
  script_tag(name:"creation_date", value:"2023-12-04 04:12:23 +0000 (Mon, 04 Dec 2023)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-11-14 15:22:50 +0000 (Tue, 14 Nov 2023)");

  script_name("Mageia: Security Advisory (MGASA-2023-0332)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2023-0332");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2023-0332.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=32493");
  script_xref(name:"URL", value:"https://github.com/roundcube/roundcubemail/releases/tag/1.6.4");
  script_xref(name:"URL", value:"https://github.com/roundcube/roundcubemail/releases/tag/1.6.5");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'roundcubemail' package(s) announced via the MGASA-2023-0332 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated roundcubemail package fixes security vulnerabilities:

Fix cross-site scripting (XSS) vulnerability in setting Content-Type/
Content-Disposition for attachment preview/download (CVE-2023-47272)

Fix cross-site scripting (XSS) vulnerability in handling of SVG in HTML
messages. (CVE-2023-5631)

Some other errors have been fixed:
- Fix PHP8 fatal error when parsing a malformed BODYSTRUCTURE
- Fix duplicated Inbox folder on IMAP servers that do not use Inbox
 folder with all capital letters
- Fix PHP warnings
- Fix UI issue when dealing with an invalid managesieve_default_headers
 value
- Fix bug where images attached to application/smil messages weren't
 displayed
- Fix PHP string replacement error in utils/error.php
- Fix regression where smtp_user did not allow pre/post strings
 before/after %u placeholder");

  script_tag(name:"affected", value:"'roundcubemail' package(s) on Mageia 9.");

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

  if(!isnull(res = isrpmvuln(pkg:"roundcubemail", rpm:"roundcubemail~1.6.5~1.mga9", rls:"MAGEIA9"))) {
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
