# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2023.6242.2");
  script_cve_id("CVE-2023-38408");
  script_tag(name:"creation_date", value:"2023-08-01 04:09:44 +0000 (Tue, 01 Aug 2023)");
  script_version("2023-08-02T05:06:27+0000");
  script_tag(name:"last_modification", value:"2023-08-02 05:06:27 +0000 (Wed, 02 Aug 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-07-31 17:07:00 +0000 (Mon, 31 Jul 2023)");

  script_name("Ubuntu: Security Advisory (USN-6242-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.04\ LTS|16\.04\ LTS|18\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-6242-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6242-2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openssh' package(s) announced via the USN-6242-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-6242-1 fixed a vulnerability in OpenSSH. This update provides
the corresponding update for Ubuntu 14.04 LTS, Ubuntu 16.04 LTS,
and Ubuntu 18.04 LTS.

Original advisory details:

 It was discovered that OpenSSH incorrectly handled loading certain PKCS#11
 providers. If a user forwarded their ssh-agent to an untrusted system, a
 remote attacker could possibly use this issue to load arbitrary libraries
 from the user's system and execute arbitrary code.");

  script_tag(name:"affected", value:"'openssh' package(s) on Ubuntu 14.04, Ubuntu 16.04, Ubuntu 18.04.");

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

if(release == "UBUNTU14.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"openssh-client", ver:"1:6.6p1-2ubuntu2.13+esm1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU16.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"openssh-client", ver:"1:7.2p2-4ubuntu2.10+esm3", rls:"UBUNTU16.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"openssh-client", ver:"1:7.6p1-4ubuntu0.7+esm1", rls:"UBUNTU18.04 LTS"))) {
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
