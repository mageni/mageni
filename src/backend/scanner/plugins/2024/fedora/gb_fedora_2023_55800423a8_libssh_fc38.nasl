# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.885553");
  script_version("2024-01-24T14:38:46+0000");
  script_cve_id("CVE-2023-48795", "CVE-2023-6004", "CVE-2023-6918");
  script_tag(name:"cvss_base", value:"5.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:C/A:N");
  script_tag(name:"last_modification", value:"2024-01-24 14:38:46 +0000 (Wed, 24 Jan 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-12-29 03:15:00 +0000 (Fri, 29 Dec 2023)");
  script_tag(name:"creation_date", value:"2024-01-18 09:14:11 +0000 (Thu, 18 Jan 2024)");
  script_name("Fedora: Security Advisory for libssh (FEDORA-2023-55800423a8)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC38");

  script_xref(name:"Advisory-ID", value:"FEDORA-2023-55800423a8");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/LZQVUHWVWRH73YBXUQJOD6CKHDQBU3DM");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libssh'
  package(s) announced via the FEDORA-2023-55800423a8 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The ssh library was designed to be used by programmers needing a working SSH
implementation by the mean of a library. The complete control of the client is
made by the programmer. With libssh, you can remotely execute programs, transfer
files, use a secure and transparent tunnel for your remote programs. With its
Secure FTP implementation, you can play with remote files easily, without
third-party programs others than libcrypto (from openssl).");

  script_tag(name:"affected", value:"'libssh' package(s) on Fedora 38.");

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

  if(!isnull(res = isrpmvuln(pkg:"libssh", rpm:"libssh~0.10.6~2.fc38", rls:"FC38"))) {
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