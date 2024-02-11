# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2024.6592.2");
  script_cve_id("CVE-2023-6004", "CVE-2023-6918");
  script_tag(name:"creation_date", value:"2024-02-06 04:08:43 +0000 (Tue, 06 Feb 2024)");
  script_version("2024-02-06T05:05:38+0000");
  script_tag(name:"last_modification", value:"2024-02-06 05:05:38 +0000 (Tue, 06 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-01-04 20:21:35 +0000 (Thu, 04 Jan 2024)");

  script_name("Ubuntu: Security Advisory (USN-6592-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(16\.04\ LTS|18\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-6592-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6592-2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libssh' package(s) announced via the USN-6592-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-6592-1 fixed vulnerabilities in libssh. This update provides the
corresponding updates for Ubuntu 16.04 LTS and Ubuntu 18.04 LTS.

Original advisory details:

 It was discovered that libssh incorrectly handled the ProxyCommand and the
 ProxyJump features. A remote attacker could possibly use this issue to
 inject malicious code into the command of the features mentioned through
 the hostname parameter. (CVE-2023-6004)

 It was discovered that libssh incorrectly handled return codes when
 performing message digest operations. A remote attacker could possibly use
 this issue to cause libssh to crash, obtain sensitive information, or
 execute arbitrary code. (CVE-2023-6918)");

  script_tag(name:"affected", value:"'libssh' package(s) on Ubuntu 16.04, Ubuntu 18.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libssh-4", ver:"0.6.3-4.3ubuntu0.6+esm1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libssh-gcrypt-4", ver:"0.6.3-4.3ubuntu0.6+esm1", rls:"UBUNTU16.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libssh-4", ver:"0.8.0~20170825.94fa1e38-1ubuntu0.7+esm3", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libssh-gcrypt-4", ver:"0.8.0~20170825.94fa1e38-1ubuntu0.7+esm3", rls:"UBUNTU18.04 LTS"))) {
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
