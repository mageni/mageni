# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.885230");
  script_version("2023-12-07T05:05:41+0000");
  script_cve_id("CVE-2023-34058", "CVE-2023-34059");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:H/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-12-07 05:05:41 +0000 (Thu, 07 Dec 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:A/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-11-08 04:15:00 +0000 (Wed, 08 Nov 2023)");
  script_tag(name:"creation_date", value:"2023-11-08 02:14:51 +0000 (Wed, 08 Nov 2023)");
  script_name("Fedora: Security Advisory for open-vm-tools (FEDORA-2023-1ed0ec0035)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC37");

  script_xref(name:"Advisory-ID", value:"FEDORA-2023-1ed0ec0035");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/WLTKVTRKQW2GD2274H3UOW6XU4E62GSK");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'open-vm-tools'
  package(s) announced via the FEDORA-2023-1ed0ec0035 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The open-vm-tools project is an open source implementation of VMware Tools. It
is a suite of open source virtualization utilities and drivers to improve the
functionality, user experience and administration of VMware virtual machines.
This package contains only the core user-space programs and libraries of
open-vm-tools.");

  script_tag(name:"affected", value:"'open-vm-tools' package(s) on Fedora 37.");

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

  if(!isnull(res = isrpmvuln(pkg:"open-vm-tools", rpm:"open-vm-tools~12.3.0~3.fc37", rls:"FC37"))) {
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