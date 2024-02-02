# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.885263");
  script_version("2023-12-07T05:05:41+0000");
  script_cve_id("CVE-2023-38802", "CVE-2023-41358", "CVE-2023-41359", "CVE-2023-41360", "CVE-2023-41909", "CVE-2023-31489", "CVE-2023-31490");
  script_tag(name:"cvss_base", value:"9.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:C");
  script_tag(name:"last_modification", value:"2023-12-07 05:05:41 +0000 (Thu, 07 Dec 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-08-30 00:44:00 +0000 (Wed, 30 Aug 2023)");
  script_tag(name:"creation_date", value:"2023-11-16 02:16:22 +0000 (Thu, 16 Nov 2023)");
  script_name("Fedora: Security Advisory for frr (FEDORA-2023-61abba57d8)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC38");

  script_xref(name:"Advisory-ID", value:"FEDORA-2023-61abba57d8");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/WXR6PIVY4SWO7HDT4EY733H4X32SCPM4");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'frr'
  package(s) announced via the FEDORA-2023-61abba57d8 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"FRRouting is free software that manages TCP/IP based routing protocols. It takes
a multi-server and multi-threaded approach to resolve the current complexity
of the Internet.

FRRouting supports BGP4, OSPFv2, OSPFv3, ISIS, RIP, RIPng, PIM, NHRP, PBR, EIGRP and BFD.

FRRouting is a fork of Quagga.");

  script_tag(name:"affected", value:"'frr' package(s) on Fedora 38.");

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

  if(!isnull(res = isrpmvuln(pkg:"frr", rpm:"frr~8.5.3~1.fc38", rls:"FC38"))) {
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