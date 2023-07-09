# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2023.6180.1");
  script_cve_id("CVE-2019-19721", "CVE-2020-13428", "CVE-2021-25801", "CVE-2021-25802", "CVE-2021-25803", "CVE-2021-25804", "CVE-2022-41325");
  script_tag(name:"creation_date", value:"2023-06-22 04:09:38 +0000 (Thu, 22 Jun 2023)");
  script_version("2023-07-05T05:06:18+0000");
  script_tag(name:"last_modification", value:"2023-07-05 05:06:18 +0000 (Wed, 05 Jul 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-12-08 16:44:00 +0000 (Thu, 08 Dec 2022)");

  script_name("Ubuntu: Security Advisory (USN-6180-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(16\.04\ LTS|18\.04\ LTS|20\.04\ LTS|22\.04\ LTS|22\.10)");

  script_xref(name:"Advisory-ID", value:"USN-6180-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6180-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'vlc' package(s) announced via the USN-6180-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that VLC could be made to read out of bounds when
decoding image files. If a user were tricked into opening a crafted image
file, a remote attacker could possibly use this issue to cause VLC to
crash, leading to a denial of service. This issue only affected Ubuntu
16.04 LTS and Ubuntu 18.04 LTS. (CVE-2019-19721)

It was discovered that VLC could be made to write out of bounds when
processing H.264 video files. If a user were tricked into opening a
crafted H.264 video file, a remote attacker could possibly use this issue
to cause VLC to crash, leading to a denial of service, or possibly
execute arbitrary code. This issue only affected Ubuntu 18.04 LTS and
Ubuntu 20.04 LTS. (CVE-2020-13428)

It was discovered that VLC could be made to read out of bounds when
processing AVI video files. If a user were tricked into opening a crafted
AVI video file, a remote attacker could possibly use this issue to cause
VLC to crash, leading to a denial of service. This issue only affected
Ubuntu 16.04 LTS, Ubuntu 18.04 LTS, and Ubuntu 20.04 LTS. (CVE-2021-25801,
CVE-2021-25802, CVE-2021-25803, CVE-2021-25804)

It was discovered that the VNC module of VLC contained an arithmetic
overflow. If a user were tricked into opening a crafted playlist or
connecting to a rouge VNC server, a remote attacker could possibly use
this issue to cause VLC to crash, leading to a denial of service, or
possibly execute arbitrary code. (CVE-2022-41325)");

  script_tag(name:"affected", value:"'vlc' package(s) on Ubuntu 16.04, Ubuntu 18.04, Ubuntu 20.04, Ubuntu 22.04, Ubuntu 22.10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"vlc", ver:"2.2.2-5ubuntu0.16.04.5+esm2", rls:"UBUNTU16.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"vlc", ver:"3.0.8-0ubuntu18.04.1+esm1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"vlc-plugin-access-extra", ver:"3.0.8-0ubuntu18.04.1+esm1", rls:"UBUNTU18.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"vlc", ver:"3.0.9.2-1ubuntu0.1~esm1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"vlc-plugin-access-extra", ver:"3.0.9.2-1ubuntu0.1~esm1", rls:"UBUNTU20.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"vlc", ver:"3.0.16-1ubuntu0.1~esm1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"vlc-plugin-access-extra", ver:"3.0.16-1ubuntu0.1~esm1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU22.10") {

  if(!isnull(res = isdpkgvuln(pkg:"vlc", ver:"3.0.17.4-5ubuntu0.1", rls:"UBUNTU22.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"vlc-plugin-access-extra", ver:"3.0.17.4-5ubuntu0.1", rls:"UBUNTU22.10"))) {
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
