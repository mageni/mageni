# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.885039");
  script_version("2023-10-27T16:11:33+0000");
  script_cve_id("CVE-2023-5218", "CVE-2023-5487", "CVE-2023-5484", "CVE-2023-5475", "CVE-2023-5483", "CVE-2023-5481", "CVE-2023-5476", "CVE-2023-5474", "CVE-2023-5479", "CVE-2023-5485", "CVE-2023-5478", "CVE-2023-5477", "CVE-2023-5486", "CVE-2023-5473", "CVE-2023-5346");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-10-27 16:11:33 +0000 (Fri, 27 Oct 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-10-13 02:15:00 +0000 (Fri, 13 Oct 2023)");
  script_tag(name:"creation_date", value:"2023-10-22 01:18:12 +0000 (Sun, 22 Oct 2023)");
  script_name("Fedora: Security Advisory for chromium (FEDORA-2023-8c9fd2a001)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC38");

  script_xref(name:"Advisory-ID", value:"FEDORA-2023-8c9fd2a001");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/M4GHJ3FK5NPHDRUR4OJOI4UU6FKSOOGG");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'chromium'
  package(s) announced via the FEDORA-2023-8c9fd2a001 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Chromium is an open-source web browser, powered by WebKit (Blink).");

  script_tag(name:"affected", value:"'chromium' package(s) on Fedora 38.");

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

  if(!isnull(res = isrpmvuln(pkg:"chromium", rpm:"chromium~118.0.5993.70~2.fc38", rls:"FC38"))) {
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