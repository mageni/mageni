# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2023.0334");
  script_cve_id("CVE-2023-42822");
  script_tag(name:"creation_date", value:"2023-12-04 04:12:23 +0000 (Mon, 04 Dec 2023)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-10-02 18:54:32 +0000 (Mon, 02 Oct 2023)");

  script_name("Mageia: Security Advisory (MGASA-2023-0334)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2023-0334");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2023-0334.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=32575");
  script_xref(name:"URL", value:"https://lwn.net/Articles/952920/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'xrdp' package(s) announced via the MGASA-2023-0334 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The updated packages fix a security vulnerability

Access to the font glyphs in xrdp_painter.c is not bounds-checked. Since
some of this data is controllable by the user, this can result in an
out-of-bounds read within the xrdp executable. The vulnerability allows
an out-of-bounds read within a potentially privileged process. On
non-Debian platforms, xrdp tends to run as root. Potentially an
out-of-bounds write can follow the out-of-bounds read. There is no
denial-of-service impact, providing xrdp is running in forking mode.
(CVE-2023-42822)");

  script_tag(name:"affected", value:"'xrdp' package(s) on Mageia 9.");

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

  if(!isnull(res = isrpmvuln(pkg:"xrdp", rpm:"xrdp~0.9.23.1~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xrdp-devel", rpm:"xrdp-devel~0.9.23.1~1.mga9", rls:"MAGEIA9"))) {
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
