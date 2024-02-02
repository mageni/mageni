# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.885485");
  script_version("2023-12-29T16:09:56+0000");
  script_cve_id("CVE-2023-40660", "CVE-2023-4535", "CVE-2023-40661");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-12-29 16:09:56 +0000 (Fri, 29 Dec 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:P/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-11-14 17:12:00 +0000 (Tue, 14 Nov 2023)");
  script_tag(name:"creation_date", value:"2023-12-24 02:16:24 +0000 (Sun, 24 Dec 2023)");
  script_name("Fedora: Security Advisory for opensc (FEDORA-2023-c7e4c9af51)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC38");

  script_xref(name:"Advisory-ID", value:"FEDORA-2023-c7e4c9af51");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/3CPQOMCDWFRBMEFR5VK4N5MMXXU42ODE");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'opensc'
  package(s) announced via the FEDORA-2023-c7e4c9af51 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"OpenSC provides a set of libraries and utilities to work with smart cards. Its
main focus is on cards that support cryptographic operations, and facilitate
their use in security applications such as authentication, mail encryption and
digital signatures. OpenSC implements the PKCS#11 API so applications
supporting this API (such as Mozilla Firefox and Thunderbird) can use it. On
the card OpenSC implements the PKCS#15 standard and aims to be compatible with
every software/card that does so, too.");

  script_tag(name:"affected", value:"'opensc' package(s) on Fedora 38.");

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

  if(!isnull(res = isrpmvuln(pkg:"opensc", rpm:"opensc~0.24.0~1.fc38", rls:"FC38"))) {
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