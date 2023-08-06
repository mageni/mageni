# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2023.6263.1");
  script_cve_id("CVE-2023-22006", "CVE-2023-22036", "CVE-2023-22041", "CVE-2023-22044", "CVE-2023-22045", "CVE-2023-22049", "CVE-2023-25193");
  script_tag(name:"creation_date", value:"2023-08-01 04:09:44 +0000 (Tue, 01 Aug 2023)");
  script_version("2023-08-02T05:06:27+0000");
  script_tag(name:"last_modification", value:"2023-08-02 05:06:27 +0000 (Wed, 02 Aug 2023)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-02-13 14:53:00 +0000 (Mon, 13 Feb 2023)");

  script_name("Ubuntu: Security Advisory (USN-6263-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(16\.04\ LTS|18\.04\ LTS|20\.04\ LTS|22\.04\ LTS|23\.04)");

  script_xref(name:"Advisory-ID", value:"USN-6263-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6263-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openjdk-8, openjdk-17, openjdk-lts' package(s) announced via the USN-6263-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Motoyasu Saburi discovered that OpenJDK incorrectly handled special
characters in file name parameters. An attacker could possibly use
this issue to insert, edit or obtain sensitive information. This issue
only affected OpenJDK 11 and OpenJDK 17. (CVE-2023-22006)

Eirik Bjorsnos discovered that OpenJDK incorrectly handled certain ZIP
archives. An attacker could possibly use this issue to cause a denial
of service. This issue only affected OpenJDK 11 and OpenJDK 17.
(CVE-2023-22036)

David Stancu discovered that OpenJDK had a flaw in the AES cipher
implementation. An attacker could possibly use this issue to obtain
sensitive information. This issue only affected OpenJDK 11 and OpenJDK 17.
(CVE-2023-22041)

Zhiqiang Zang discovered that OpenJDK incorrectly handled array accesses
when using the binary '%' operator. An attacker could possibly use this
issue to obtain sensitive information. This issue only affected OpenJDK 17.
(CVE-2023-22044)

Zhiqiang Zang discovered that OpenJDK incorrectly handled array accesses.
An attacker could possibly use this issue to obtain sensitive information.
(CVE-2023-22045)

It was discovered that OpenJDK incorrectly sanitized URIs strings. An
attacker could possibly use this issue to insert, edit or obtain sensitive
information. (CVE-2023-22049)

It was discovered that OpenJDK incorrectly handled certain glyphs. An
attacker could possibly use this issue to cause a denial of service.
This issue only affected OpenJDK 11 and OpenJDK 17.
(CVE-2023-25193)");

  script_tag(name:"affected", value:"'openjdk-8, openjdk-17, openjdk-lts' package(s) on Ubuntu 16.04, Ubuntu 18.04, Ubuntu 20.04, Ubuntu 22.04, Ubuntu 23.04.");

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

if(release == "UBUNTU16.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-8-jdk", ver:"8u382-ga-1~16.04.1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-8-jre", ver:"8u382-ga-1~16.04.1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-8-jre-headless", ver:"8u382-ga-1~16.04.1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-8-jre-zero", ver:"8u382-ga-1~16.04.1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU18.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-11-jdk", ver:"11.0.20+8-1ubuntu1~18.04", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-11-jre", ver:"11.0.20+8-1ubuntu1~18.04", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-11-jre-headless", ver:"11.0.20+8-1ubuntu1~18.04", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-11-jre-zero", ver:"11.0.20+8-1ubuntu1~18.04", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-17-jdk", ver:"17.0.8+7-1~18.04", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-17-jre", ver:"17.0.8+7-1~18.04", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-17-jre-headless", ver:"17.0.8+7-1~18.04", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-17-jre-zero", ver:"17.0.8+7-1~18.04", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-8-jdk", ver:"8u382-ga-1~18.04.1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-8-jre", ver:"8u382-ga-1~18.04.1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-8-jre-headless", ver:"8u382-ga-1~18.04.1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-8-jre-zero", ver:"8u382-ga-1~18.04.1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU20.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-11-jdk", ver:"11.0.20+8-1ubuntu1~20.04", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-11-jre", ver:"11.0.20+8-1ubuntu1~20.04", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-11-jre-headless", ver:"11.0.20+8-1ubuntu1~20.04", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-11-jre-zero", ver:"11.0.20+8-1ubuntu1~20.04", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-17-jdk", ver:"17.0.8+7-1~20.04.2", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-17-jre", ver:"17.0.8+7-1~20.04.2", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-17-jre-headless", ver:"17.0.8+7-1~20.04.2", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-17-jre-zero", ver:"17.0.8+7-1~20.04.2", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-8-jdk", ver:"8u382-ga-1~20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-8-jre", ver:"8u382-ga-1~20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-8-jre-headless", ver:"8u382-ga-1~20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-8-jre-zero", ver:"8u382-ga-1~20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU22.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-11-jdk", ver:"11.0.20+8-1ubuntu1~22.04", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-11-jre", ver:"11.0.20+8-1ubuntu1~22.04", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-11-jre-headless", ver:"11.0.20+8-1ubuntu1~22.04", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-11-jre-zero", ver:"11.0.20+8-1ubuntu1~22.04", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-17-jdk", ver:"17.0.8+7-1~22.04", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-17-jre", ver:"17.0.8+7-1~22.04", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-17-jre-headless", ver:"17.0.8+7-1~22.04", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-17-jre-zero", ver:"17.0.8+7-1~22.04", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-8-jdk", ver:"8u382-ga-1~22.04.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-8-jre", ver:"8u382-ga-1~22.04.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-8-jre-headless", ver:"8u382-ga-1~22.04.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-8-jre-zero", ver:"8u382-ga-1~22.04.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU23.04") {

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-11-jdk", ver:"11.0.20+8-1ubuntu1~23.04", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-11-jre", ver:"11.0.20+8-1ubuntu1~23.04", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-11-jre-headless", ver:"11.0.20+8-1ubuntu1~23.04", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-11-jre-zero", ver:"11.0.20+8-1ubuntu1~23.04", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-17-jdk", ver:"17.0.8+7-1~23.04", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-17-jre", ver:"17.0.8+7-1~23.04", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-17-jre-headless", ver:"17.0.8+7-1~23.04", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-17-jre-zero", ver:"17.0.8+7-1~23.04", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-8-jdk", ver:"8u382-ga-1~23.04.1", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-8-jre", ver:"8u382-ga-1~23.04.1", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-8-jre-headless", ver:"8u382-ga-1~23.04.1", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-8-jre-zero", ver:"8u382-ga-1~23.04.1", rls:"UBUNTU23.04"))) {
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
