# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2023.6183.2");
  script_cve_id("CVE-2023-2828", "CVE-2023-2911");
  script_tag(name:"creation_date", value:"2023-07-19 04:14:28 +0000 (Wed, 19 Jul 2023)");
  script_version("2023-07-19T05:05:15+0000");
  script_tag(name:"last_modification", value:"2023-07-19 05:05:15 +0000 (Wed, 19 Jul 2023)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-06-21 21:15:00 +0000 (Wed, 21 Jun 2023)");

  script_name("Ubuntu: Security Advisory (USN-6183-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.04\ LTS|16\.04\ LTS|18\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-6183-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6183-2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'bind9' package(s) announced via the USN-6183-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-6183-1 fixed vulnerabilities in Bind. This update provides the
corresponding updates for Ubuntu 14.04 LTS, Ubuntu 16.04 LTS and Ubuntu 18.04
LTS.

Original advisory details:

 Shoham Danino, Anat Bremler-Barr, Yehuda Afek, and Yuval Shavitt discovered
 that Bind incorrectly handled the cache size limit. A remote attacker could
 possibly use this issue to consume memory, leading to a denial of service.
 (CVE-2023-2828)

 It was discovered that Bind incorrectly handled the recursive-clients
 quota. A remote attacker could possibly use this issue to cause Bind to
 crash, resulting in a denial of service. This issue only affected Ubuntu
 22.04 LTS, Ubuntu 22.10, and Ubuntu 23.04. (CVE-2023-2911)");

  script_tag(name:"affected", value:"'bind9' package(s) on Ubuntu 14.04, Ubuntu 16.04, Ubuntu 18.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"bind9", ver:"1:9.9.5.dfsg-3ubuntu0.19+esm10", rls:"UBUNTU14.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"bind9", ver:"1:9.10.3.dfsg.P4-8ubuntu1.19+esm6", rls:"UBUNTU16.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"bind9", ver:"1:9.11.3+dfsg-1ubuntu1.19+esm1", rls:"UBUNTU18.04 LTS"))) {
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
