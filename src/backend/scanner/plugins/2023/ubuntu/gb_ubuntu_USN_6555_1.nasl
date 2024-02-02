# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2023.6555.1");
  script_cve_id("CVE-2023-6377", "CVE-2023-6478");
  script_tag(name:"creation_date", value:"2023-12-14 04:08:36 +0000 (Thu, 14 Dec 2023)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-12-13 07:15:30 +0000 (Wed, 13 Dec 2023)");

  script_name("Ubuntu: Security Advisory (USN-6555-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(20\.04\ LTS|22\.04\ LTS|23\.04|23\.10)");

  script_xref(name:"Advisory-ID", value:"USN-6555-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6555-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'xorg-server, xwayland' package(s) announced via the USN-6555-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Jan-Niklas Sohn discovered that the X.Org X Server incorrectly handled XKB
button actions. An attacker could possibly use this issue to cause the X
Server to crash, execute arbitrary code, or escalate privileges.
(CVE-2023-6377)

Jan-Niklas Sohn discovered that the X.Org X Server incorrectly handled
memory when processing the RRChangeOutputProperty and
RRChangeProviderProperty APIs. An attacker could possibly use this issue to
cause the X Server to crash, or obtain sensitive information.
(CVE-2023-6478)");

  script_tag(name:"affected", value:"'xorg-server, xwayland' package(s) on Ubuntu 20.04, Ubuntu 22.04, Ubuntu 23.04, Ubuntu 23.10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"xserver-xorg-core", ver:"2:1.20.13-1ubuntu1~20.04.12", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xwayland", ver:"2:1.20.13-1ubuntu1~20.04.12", rls:"UBUNTU20.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"xserver-xorg-core", ver:"2:21.1.4-2ubuntu1.7~22.04.5", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xwayland", ver:"2:22.1.1-1ubuntu0.9", rls:"UBUNTU22.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"xserver-xorg-core", ver:"2:21.1.7-1ubuntu3.4", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xwayland", ver:"2:22.1.8-1ubuntu1.3", rls:"UBUNTU23.04"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"xserver-xorg-core", ver:"2:21.1.7-3ubuntu2.4", rls:"UBUNTU23.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xwayland", ver:"2:23.2.0-1ubuntu0.3", rls:"UBUNTU23.10"))) {
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
