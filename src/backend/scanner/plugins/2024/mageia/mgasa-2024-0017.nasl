# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2024.0017");
  script_cve_id("CVE-2024-0517", "CVE-2024-0518", "CVE-2024-0519");
  script_tag(name:"creation_date", value:"2024-01-26 04:13:03 +0000 (Fri, 26 Jan 2024)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-01-22 19:53:33 +0000 (Mon, 22 Jan 2024)");

  script_name("Mageia: Security Advisory (MGASA-2024-0017)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2024-0017");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2024-0017.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=32725");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2024/01/stable-channel-update-for-desktop_16.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'chromium-browser-stable' package(s) announced via the MGASA-2024-0017 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The chromium-browser-stable package has been updated to the
120.0.6099.224 release. 4 vulnerabilities are fixed, some of them are
listed below:
High CVE-2024-0517: Out of bounds write in V8. Reported by Toan (suto)
Pham of Qrious Secure on 2024-01-06.
High CVE-2024-0518: Type Confusion in V8. Reported by Ganjiang
Zhou(@refrain_areu) of ChaMd5-H1 team on 2023-12-03.
High CVE-2024-0519: Out of bounds memory access in V8. Reported by
Anonymous on 2024-01-11.
Google is aware of reports that an exploit for CVE-2024-0519 exists in
the wild.");

  script_tag(name:"affected", value:"'chromium-browser-stable' package(s) on Mageia 9.");

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

  if(!isnull(res = isrpmvuln(pkg:"chromium-browser", rpm:"chromium-browser~120.0.6099.224~1.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-browser-stable", rpm:"chromium-browser-stable~120.0.6099.224~1.mga9.tainted", rls:"MAGEIA9"))) {
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
