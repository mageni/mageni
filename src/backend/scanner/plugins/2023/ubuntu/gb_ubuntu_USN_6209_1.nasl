# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2023.6209.1");
  script_cve_id("CVE-2021-40391", "CVE-2021-40393", "CVE-2021-40394", "CVE-2021-40400", "CVE-2021-40401", "CVE-2021-40403");
  script_tag(name:"creation_date", value:"2023-07-10 04:09:33 +0000 (Mon, 10 Jul 2023)");
  script_version("2023-07-10T08:07:42+0000");
  script_tag(name:"last_modification", value:"2023-07-10 08:07:42 +0000 (Mon, 10 Jul 2023)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-10-14 02:20:00 +0000 (Fri, 14 Oct 2022)");

  script_name("Ubuntu: Security Advisory (USN-6209-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.04\ LTS|16\.04\ LTS|18\.04\ LTS|20\.04\ LTS|22\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-6209-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6209-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gerbv' package(s) announced via the USN-6209-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Claudio Bozzato discovered that Gerbv incorrectly handled certain Gerber
files. An attacker could possibly use this issue to crash Gerbv (resulting
in a denial of service), or execute arbitrary code. This issue only
affected Ubuntu 14.04 LTS, Ubuntu 16.04 LTS, Ubuntu 18.04 LTS, and Ubuntu
20.04 LTS. (CVE-2021-40391, CVE-2021-40394)

Claudio Bozzato discovered that Gerbv incorrectly handled certain Gerber
files. An attacker could possibly use this issue to disclose information,
crash Gerbv (resulting in a denial of service), or execute arbitrary code.
This issue only affected Ubuntu 14.04 LTS, Ubuntu 16.04 LTS, Ubuntu 18.04
LTS, and Ubuntu 20.04 LTS. (CVE-2021-40393)

Claudio Bozzato discovered that Gerbv incorrectly handled certain Gerber
files. An attacker could possibly use this issue to disclose information.
(CVE-2021-40400, CVE-2021-40403)

Claudio Bozzato discovered that Gerbv incorrectly handled certain Gerber
files. An attacker could possibly use this issue to disclose information,
crash Gerbv (resulting in a denial of service), or execute arbitrary code.
(CVE-2021-40401)");

  script_tag(name:"affected", value:"'gerbv' package(s) on Ubuntu 14.04, Ubuntu 16.04, Ubuntu 18.04, Ubuntu 20.04, Ubuntu 22.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"gerbv", ver:"2.6.0-1ubuntu0.14.04.1~esm1", rls:"UBUNTU14.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"gerbv", ver:"2.6.0-1ubuntu0.16.04.1~esm1", rls:"UBUNTU16.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"gerbv", ver:"2.6.1-3ubuntu0.1~esm1", rls:"UBUNTU18.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"gerbv", ver:"2.7.0-1ubuntu0.1", rls:"UBUNTU20.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"gerbv", ver:"2.8.2-1ubuntu0.1~esm1", rls:"UBUNTU22.04 LTS"))) {
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
