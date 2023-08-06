# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2023.6272.1");
  script_cve_id("CVE-2023-22006", "CVE-2023-22036", "CVE-2023-22041", "CVE-2023-22044", "CVE-2023-22045", "CVE-2023-22049", "CVE-2023-25193");
  script_tag(name:"creation_date", value:"2023-08-04 04:08:45 +0000 (Fri, 04 Aug 2023)");
  script_version("2023-08-04T05:06:23+0000");
  script_tag(name:"last_modification", value:"2023-08-04 05:06:23 +0000 (Fri, 04 Aug 2023)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-02-13 14:53:00 +0000 (Mon, 13 Feb 2023)");

  script_name("Ubuntu: Security Advisory (USN-6272-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU23\.04");

  script_xref(name:"Advisory-ID", value:"USN-6272-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6272-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openjdk-20' package(s) announced via the USN-6272-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Motoyasu Saburi discovered that OpenJDK 20 incorrectly handled special
characters in file name parameters. An attacker could possibly use
this issue to insert, edit or obtain sensitive information.
(CVE-2023-22006)

Eirik Bjorsnos discovered that OpenJDK 20 incorrectly handled certain ZIP
archives. An attacker could possibly use this issue to cause a denial
of service. (CVE-2023-22036)

David Stancu discovered that OpenJDK 20 had a flaw in the AES cipher
implementation. An attacker could possibly use this issue to obtain
sensitive information. (CVE-2023-22041)

Zhiqiang Zang discovered that OpenJDK 20 incorrectly handled array accesses
when using the binary '%' operator. An attacker could possibly use this
issue to obtain sensitive information. (CVE-2023-22044)

Zhiqiang Zang discovered that OpenJDK 20 incorrectly handled array accesses.
An attacker could possibly use this issue to obtain sensitive information.
(CVE-2023-22045)

It was discovered that OpenJDK 20 incorrectly sanitized URIs strings. An
attacker could possibly use this issue to insert, edit or obtain sensitive
information. (CVE-2023-22049)

It was discovered that OpenJDK 20 incorrectly handled certain glyphs. An
attacker could possibly use this issue to cause a denial of service.
(CVE-2023-25193)");

  script_tag(name:"affected", value:"'openjdk-20' package(s) on Ubuntu 23.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "UBUNTU23.04") {

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-20-jdk", ver:"20.0.2+9+ds1-0ubuntu1~23.04", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-20-jre", ver:"20.0.2+9+ds1-0ubuntu1~23.04", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-20-jre-headless", ver:"20.0.2+9+ds1-0ubuntu1~23.04", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-20-jre-zero", ver:"20.0.2+9+ds1-0ubuntu1~23.04", rls:"UBUNTU23.04"))) {
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
