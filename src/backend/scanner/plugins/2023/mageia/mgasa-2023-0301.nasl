# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2023.0301");
  script_cve_id("CVE-2023-45145");
  script_tag(name:"creation_date", value:"2023-10-25 04:11:52 +0000 (Wed, 25 Oct 2023)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"2.4");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-10-30 12:50:12 +0000 (Mon, 30 Oct 2023)");

  script_name("Mageia: Security Advisory (MGASA-2023-0301)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2023-0301");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2023-0301.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=32406");
  script_xref(name:"URL", value:"https://github.com/redis/redis/releases/tag/7.0.14");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'redis' package(s) announced via the MGASA-2023-0301 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Redis upstream published a fix for CVE-2023-45145.

CVE-2023-45145: The wrong order of listen(2) and chmod(2) calls creates
a race condition that can be used by another process to bypass desired
Unix socket permissions on startup.");

  script_tag(name:"affected", value:"'redis' package(s) on Mageia 9.");

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

  if(!isnull(res = isrpmvuln(pkg:"redis", rpm:"redis~7.0.14~1.mga9", rls:"MAGEIA9"))) {
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
