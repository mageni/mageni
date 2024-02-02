# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2024.6560.2");
  script_cve_id("CVE-2023-48795", "CVE-2023-51385");
  script_tag(name:"creation_date", value:"2024-01-12 04:09:10 +0000 (Fri, 12 Jan 2024)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-01-03 19:40:07 +0000 (Wed, 03 Jan 2024)");

  script_name("Ubuntu: Security Advisory (USN-6560-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(16\.04\ LTS|18\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-6560-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6560-2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openssh' package(s) announced via the USN-6560-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-6560-1 fixed several vulnerabilities in OpenSSH. This update provides
the corresponding update for Ubuntu 16.04 LTS and Ubuntu 18.04 LTS.

Original advisory details:

 Fabian Baumer, Marcus Brinkmann, Jorg Schwenk discovered that the SSH
 protocol was vulnerable to a prefix truncation attack. If a remote attacker
 was able to intercept SSH communications, extension negotiation messages
 could be truncated, possibly leading to certain algorithms and features
 being downgraded. This issue is known as the Terrapin attack. This update
 adds protocol extensions to mitigate this issue. (CVE-2023-48795)

 It was discovered that OpenSSH incorrectly handled user names or host names
 with shell metacharacters. An attacker could possibly use this issue to
 perform OS command injection. This only affected Ubuntu 18.04 LTS. (CVE-2023-51385)");

  script_tag(name:"affected", value:"'openssh' package(s) on Ubuntu 16.04, Ubuntu 18.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"openssh-client", ver:"1:7.2p2-4ubuntu2.10+esm5", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openssh-server", ver:"1:7.2p2-4ubuntu2.10+esm5", rls:"UBUNTU16.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"openssh-client", ver:"1:7.6p1-4ubuntu0.7+esm3", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openssh-server", ver:"1:7.6p1-4ubuntu0.7+esm3", rls:"UBUNTU18.04 LTS"))) {
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
