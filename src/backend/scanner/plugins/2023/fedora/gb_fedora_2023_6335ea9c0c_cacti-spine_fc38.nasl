# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.885021");
  script_version("2023-10-20T16:09:12+0000");
  script_cve_id("CVE-2023-39512", "CVE-2023-39514", "CVE-2023-39513", "CVE-2023-39515", "CVE-2023-39359", "CVE-2023-39360", "CVE-2023-39361", "CVE-2023-39366", "CVE-2023-39510", "CVE-2023-39357", "CVE-2023-39358", "CVE-2023-39364", "CVE-2023-39365", "CVE-2023-30534", "CVE-2023-31132", "CVE-2023-39362", "CVE-2023-39516", "CVE-2023-39511");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-10-20 16:09:12 +0000 (Fri, 20 Oct 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-09-08 17:42:00 +0000 (Fri, 08 Sep 2023)");
  script_tag(name:"creation_date", value:"2023-10-16 01:17:07 +0000 (Mon, 16 Oct 2023)");
  script_name("Fedora: Security Advisory for cacti-spine (FEDORA-2023-6335ea9c0c)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC38");

  script_xref(name:"Advisory-ID", value:"FEDORA-2023-6335ea9c0c");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/CFH3J2WVBKY4ZJNMARVOWJQK6PSLPHFH");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'cacti-spine'
  package(s) announced via the FEDORA-2023-6335ea9c0c advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Spine is a supplemental poller for Cacti that makes use of pthreads to achieve
excellent performance.");

  script_tag(name:"affected", value:"'cacti-spine' package(s) on Fedora 38.");

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

  if(!isnull(res = isrpmvuln(pkg:"cacti-spine", rpm:"cacti-spine~1.2.25~1.fc38", rls:"FC38"))) {
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