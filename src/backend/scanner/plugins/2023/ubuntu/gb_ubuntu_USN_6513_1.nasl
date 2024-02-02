# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2023.6513.1");
  script_cve_id("CVE-2022-48564", "CVE-2023-40217");
  script_tag(name:"creation_date", value:"2023-11-24 04:08:40 +0000 (Fri, 24 Nov 2023)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-08-26 02:19:42 +0000 (Sat, 26 Aug 2023)");

  script_name("Ubuntu: Security Advisory (USN-6513-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.04\ LTS|16\.04\ LTS|18\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-6513-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6513-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python2.7, python3.5, python3.6' package(s) announced via the USN-6513-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that Python incorrectly handled certain plist files.
If a user or an automated system were tricked into processing a specially
crafted plist file, an attacker could possibly use this issue to consume
resources, resulting in a denial of service. (CVE-2022-48564)

It was discovered that Python instances of ssl.SSLSocket were vulnerable
to a bypass of the TLS handshake. An attacker could possibly use this
issue to cause applications to treat unauthenticated received data before
TLS handshake as authenticated data after TLS handshake. (CVE-2023-40217)");

  script_tag(name:"affected", value:"'python2.7, python3.5, python3.6' package(s) on Ubuntu 14.04, Ubuntu 16.04, Ubuntu 18.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"python2.7", ver:"2.7.6-8ubuntu0.6+esm18", rls:"UBUNTU14.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"python2.7", ver:"2.7.12-1ubuntu0~16.04.18+esm9", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3.5", ver:"3.5.2-2ubuntu0~16.04.13+esm12", rls:"UBUNTU16.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"python2.7", ver:"2.7.17-1~18.04ubuntu1.13+esm4", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3.6", ver:"3.6.9-1~18.04ubuntu1.13+esm1", rls:"UBUNTU18.04 LTS"))) {
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
