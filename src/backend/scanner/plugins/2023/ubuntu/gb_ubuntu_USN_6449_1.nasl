# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2023.6449.1");
  script_cve_id("CVE-2020-20898", "CVE-2020-22038", "CVE-2021-38090", "CVE-2021-38091", "CVE-2021-38092", "CVE-2021-38093", "CVE-2021-38094", "CVE-2022-48434");
  script_tag(name:"creation_date", value:"2023-10-25 04:08:37 +0000 (Wed, 25 Oct 2023)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-09-23 15:09:44 +0000 (Thu, 23 Sep 2021)");

  script_name("Ubuntu: Security Advisory (USN-6449-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(18\.04\ LTS|20\.04\ LTS|22\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-6449-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6449-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ffmpeg' package(s) announced via the USN-6449-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that FFmpeg incorrectly managed memory resulting
in a memory leak. An attacker could possibly use this issue to cause
a denial of service via application crash. This issue only
affected Ubuntu 18.04 LTS and Ubuntu 20.04 LTS. (CVE-2020-22038)

It was discovered that FFmpeg incorrectly handled certain input files,
leading to an integer overflow. An attacker could possibly use this issue
to cause a denial of service via application crash. This issue only
affected Ubuntu 20.04 LTS. (CVE-2020-20898, CVE-2021-38090,
CVE-2021-38091, CVE-2021-38092, CVE-2021-38093, CVE-2021-38094)

It was discovered that FFmpeg incorrectly managed memory, resulting in
a memory leak. If a user or automated system were tricked into
processing a specially crafted input file, a remote attacker could
possibly use this issue to cause a denial of service, or execute
arbitrary code. (CVE-2022-48434)");

  script_tag(name:"affected", value:"'ffmpeg' package(s) on Ubuntu 18.04, Ubuntu 20.04, Ubuntu 22.04.");

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

if(release == "UBUNTU18.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"ffmpeg", ver:"7:3.4.11-0ubuntu0.1+esm3", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libavcodec-extra", ver:"7:3.4.11-0ubuntu0.1+esm3", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libavcodec-extra57", ver:"7:3.4.11-0ubuntu0.1+esm3", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libavcodec57", ver:"7:3.4.11-0ubuntu0.1+esm3", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libavdevice57", ver:"7:3.4.11-0ubuntu0.1+esm3", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libavfilter-extra", ver:"7:3.4.11-0ubuntu0.1+esm3", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libavfilter-extra6", ver:"7:3.4.11-0ubuntu0.1+esm3", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libavfilter6", ver:"7:3.4.11-0ubuntu0.1+esm3", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libavformat57", ver:"7:3.4.11-0ubuntu0.1+esm3", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libavresample3", ver:"7:3.4.11-0ubuntu0.1+esm3", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libavutil55", ver:"7:3.4.11-0ubuntu0.1+esm3", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpostproc54", ver:"7:3.4.11-0ubuntu0.1+esm3", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libswresample2", ver:"7:3.4.11-0ubuntu0.1+esm3", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libswscale4", ver:"7:3.4.11-0ubuntu0.1+esm3", rls:"UBUNTU18.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"ffmpeg", ver:"7:4.2.7-0ubuntu0.1+esm3", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libavcodec-extra", ver:"7:4.2.7-0ubuntu0.1+esm3", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libavcodec-extra58", ver:"7:4.2.7-0ubuntu0.1+esm3", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libavcodec58", ver:"7:4.2.7-0ubuntu0.1+esm3", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libavdevice58", ver:"7:4.2.7-0ubuntu0.1+esm3", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libavfilter-extra", ver:"7:4.2.7-0ubuntu0.1+esm3", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libavfilter-extra7", ver:"7:4.2.7-0ubuntu0.1+esm3", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libavfilter7", ver:"7:4.2.7-0ubuntu0.1+esm3", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libavformat58", ver:"7:4.2.7-0ubuntu0.1+esm3", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libavresample4", ver:"7:4.2.7-0ubuntu0.1+esm3", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libavutil56", ver:"7:4.2.7-0ubuntu0.1+esm3", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpostproc55", ver:"7:4.2.7-0ubuntu0.1+esm3", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libswresample3", ver:"7:4.2.7-0ubuntu0.1+esm3", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libswscale5", ver:"7:4.2.7-0ubuntu0.1+esm3", rls:"UBUNTU20.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"ffmpeg", ver:"7:4.4.2-0ubuntu0.22.04.1+esm2", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libavcodec-extra", ver:"7:4.4.2-0ubuntu0.22.04.1+esm2", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libavcodec-extra58", ver:"7:4.4.2-0ubuntu0.22.04.1+esm2", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libavcodec58", ver:"7:4.4.2-0ubuntu0.22.04.1+esm2", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libavdevice58", ver:"7:4.4.2-0ubuntu0.22.04.1+esm2", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libavfilter-extra", ver:"7:4.4.2-0ubuntu0.22.04.1+esm2", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libavfilter-extra7", ver:"7:4.4.2-0ubuntu0.22.04.1+esm2", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libavfilter7", ver:"7:4.4.2-0ubuntu0.22.04.1+esm2", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libavformat-extra", ver:"7:4.4.2-0ubuntu0.22.04.1+esm2", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libavformat-extra58", ver:"7:4.4.2-0ubuntu0.22.04.1+esm2", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libavformat58", ver:"7:4.4.2-0ubuntu0.22.04.1+esm2", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libavutil56", ver:"7:4.4.2-0ubuntu0.22.04.1+esm2", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpostproc55", ver:"7:4.4.2-0ubuntu0.22.04.1+esm2", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libswresample3", ver:"7:4.4.2-0ubuntu0.22.04.1+esm2", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libswscale-dev", ver:"7:4.4.2-0ubuntu0.22.04.1+esm2", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libswscale5", ver:"7:4.4.2-0ubuntu0.22.04.1+esm2", rls:"UBUNTU22.04 LTS"))) {
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
