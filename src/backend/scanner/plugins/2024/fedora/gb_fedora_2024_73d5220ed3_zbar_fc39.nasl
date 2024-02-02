# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.885529");
  script_version("2024-01-24T14:38:46+0000");
  script_cve_id("CVE-2023-40890", "CVE-2023-40889");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-01-24 14:38:46 +0000 (Wed, 24 Jan 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-08-31 18:35:00 +0000 (Thu, 31 Aug 2023)");
  script_tag(name:"creation_date", value:"2024-01-18 09:13:31 +0000 (Thu, 18 Jan 2024)");
  script_name("Fedora: Security Advisory for zbar (FEDORA-2024-73d5220ed3)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC39");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-73d5220ed3");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/DC7V5YCLCPB36J2KY6WLZCABFLBRB665");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'zbar'
  package(s) announced via the FEDORA-2024-73d5220ed3 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"ZBar Bar Code Reader is an open source software suite for reading bar
codes from various sources, such as video streams, image files and raw
intensity sensors. It supports EAN-13/UPC-A, UPC-E, EAN-8, Code 128,
Code 93, Code 39, Codabar, Interleaved 2 of 5, QR Code and SQ Code.");

  script_tag(name:"affected", value:"'zbar' package(s) on Fedora 39.");

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

if(release == "FC39") {

  if(!isnull(res = isrpmvuln(pkg:"zbar", rpm:"zbar~0.23.93~1.fc39", rls:"FC39"))) {
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