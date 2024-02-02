# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2024.6565.1");
  script_cve_id("CVE-2021-41617", "CVE-2023-51384", "CVE-2023-51385");
  script_tag(name:"creation_date", value:"2024-01-04 04:08:55 +0000 (Thu, 04 Jan 2024)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"4.4");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-10-07 14:46:16 +0000 (Thu, 07 Oct 2021)");

  script_name("Ubuntu: Security Advisory (USN-6565-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(20\.04\ LTS|22\.04\ LTS|23\.04|23\.10)");

  script_xref(name:"Advisory-ID", value:"USN-6565-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6565-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openssh' package(s) announced via the USN-6565-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that OpenSSH incorrectly handled supplemental groups when
running helper programs for AuthorizedKeysCommand and
AuthorizedPrincipalsCommand as a different user. An attacker could possibly
use this issue to escalate privileges. This issue only affected Ubuntu
20.04 LTS. (CVE-2021-41617)

It was discovered that OpenSSH incorrectly added destination constraints
when PKCS#11 token keys were added to ssh-agent, contrary to expectations.
This issue only affected Ubuntu 22.04 LTS, and Ubuntu 23.04.
(CVE-2023-51384)

It was discovered that OpenSSH incorrectly handled user names or host names
with shell metacharacters. An attacker could possibly use this issue to
perform OS command injection. (CVE-2023-51385)");

  script_tag(name:"affected", value:"'openssh' package(s) on Ubuntu 20.04, Ubuntu 22.04, Ubuntu 23.04, Ubuntu 23.10.");

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

if(release == "UBUNTU20.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"openssh-client", ver:"1:8.2p1-4ubuntu0.11", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openssh-server", ver:"1:8.2p1-4ubuntu0.11", rls:"UBUNTU20.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"openssh-client", ver:"1:8.9p1-3ubuntu0.6", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openssh-server", ver:"1:8.9p1-3ubuntu0.6", rls:"UBUNTU22.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"openssh-client", ver:"1:9.0p1-1ubuntu8.7", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openssh-server", ver:"1:9.0p1-1ubuntu8.7", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU23.10") {

  if(!isnull(res = isdpkgvuln(pkg:"openssh-client", ver:"1:9.3p1-1ubuntu3.2", rls:"UBUNTU23.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openssh-server", ver:"1:9.3p1-1ubuntu3.2", rls:"UBUNTU23.10"))) {
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
