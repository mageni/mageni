# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.885032");
  script_version("2023-11-21T05:05:52+0000");
  script_cve_id("CVE-2023-5539", "CVE-2023-5540", "CVE-2023-5541", "CVE-2023-5542", "CVE-2023-5543", "CVE-2023-5544", "CVE-2023-5545", "CVE-2023-5546", "CVE-2023-5547", "CVE-2023-5548", "CVE-2023-5549", "CVE-2023-5550");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-11-21 05:05:52 +0000 (Tue, 21 Nov 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-11-17 16:36:00 +0000 (Fri, 17 Nov 2023)");
  script_tag(name:"creation_date", value:"2023-10-20 01:19:27 +0000 (Fri, 20 Oct 2023)");
  script_name("Fedora: Security Advisory for moodle (FEDORA-2023-a7b0d27d18)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC37");

  script_xref(name:"Advisory-ID", value:"FEDORA-2023-a7b0d27d18");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/DUUX7FELSARYLVODBU3M2WLOK7TWAB7N");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'moodle'
  package(s) announced via the FEDORA-2023-a7b0d27d18 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Moodle is a course management system (CMS) - a free, Open Source software
package designed using sound pedagogical principles, to help educators create
effective online learning communities.");

  script_tag(name:"affected", value:"'moodle' package(s) on Fedora 37.");

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

if(release == "FC37") {

  if(!isnull(res = isrpmvuln(pkg:"moodle", rpm:"moodle~4.1.6~1.fc37", rls:"FC37"))) {
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