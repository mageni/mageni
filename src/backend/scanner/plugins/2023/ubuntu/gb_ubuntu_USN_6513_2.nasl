# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2023.6513.2");
  script_cve_id("CVE-2022-48564", "CVE-2023-40217");
  script_tag(name:"creation_date", value:"2023-11-28 04:08:50 +0000 (Tue, 28 Nov 2023)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-08-26 02:19:42 +0000 (Sat, 26 Aug 2023)");

  script_name("Ubuntu: Security Advisory (USN-6513-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(20\.04\ LTS|22\.04\ LTS|23\.04)");

  script_xref(name:"Advisory-ID", value:"USN-6513-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6513-2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python3.8, python3.10, python3.11' package(s) announced via the USN-6513-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-6513-1 fixed vulnerabilities in Python. This update provides the
corresponding updates for Ubuntu 20.04 LTS, Ubuntu 22.04 LTS, and
Ubuntu 23.04.

Original advisory details:

 It was discovered that Python incorrectly handled certain plist files.
 If a user or an automated system were tricked into processing a specially
 crafted plist file, an attacker could possibly use this issue to consume
 resources, resulting in a denial of service. (CVE-2022-48564)

 It was discovered that Python instances of ssl.SSLSocket were vulnerable
 to a bypass of the TLS handshake. An attacker could possibly use this
 issue to cause applications to treat unauthenticated received data before
 TLS handshake as authenticated data after TLS handshake. (CVE-2023-40217)");

  script_tag(name:"affected", value:"'python3.8, python3.10, python3.11' package(s) on Ubuntu 20.04, Ubuntu 22.04, Ubuntu 23.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"python3.8", ver:"3.8.10-0ubuntu1~20.04.9", rls:"UBUNTU20.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"python3.10", ver:"3.10.12-1~22.04.3", rls:"UBUNTU22.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"python3.11", ver:"3.11.4-1~23.04.1", rls:"UBUNTU23.04"))) {
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
