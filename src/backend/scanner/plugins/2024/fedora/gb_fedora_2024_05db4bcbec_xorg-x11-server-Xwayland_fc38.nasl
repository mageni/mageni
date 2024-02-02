# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.885637");
  script_version("2024-02-02T14:37:52+0000");
  script_cve_id("CVE-2023-6816", "CVE-2024-0229", "CVE-2024-21885", "CVE-2024-21886", "CVE-2024-0408", "CVE-2024-0409");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:52 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-01-26 18:50:40 +0000 (Fri, 26 Jan 2024)");
  script_tag(name:"creation_date", value:"2024-02-02 02:03:14 +0000 (Fri, 02 Feb 2024)");
  script_name("Fedora: Security Advisory for xorg-x11-server-Xwayland (FEDORA-2024-05db4bcbec)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC38");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-05db4bcbec");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/IZ75X54CN4IFYMIV7OK3JVZ57FHQIGIC");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'xorg-x11-server-Xwayland'
  package(s) announced via the FEDORA-2024-05db4bcbec advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Xwayland is an X server for running X clients under Wayland.");

  script_tag(name:"affected", value:"'xorg-x11-server-Xwayland' package(s) on Fedora 38.");

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

  if(!isnull(res = isrpmvuln(pkg:"xorg-x11-server-Xwayland", rpm:"xorg-x11-server-Xwayland~22.1.9~5.fc38", rls:"FC38"))) {
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