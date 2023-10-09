# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2023.6401.1");
  script_cve_id("CVE-2023-39350", "CVE-2023-39351", "CVE-2023-39353", "CVE-2023-39354", "CVE-2023-40181", "CVE-2023-40186", "CVE-2023-40188", "CVE-2023-40567", "CVE-2023-40569", "CVE-2023-40589");
  script_tag(name:"creation_date", value:"2023-10-05 04:08:26 +0000 (Thu, 05 Oct 2023)");
  script_version("2023-10-06T05:06:29+0000");
  script_tag(name:"last_modification", value:"2023-10-06 05:06:29 +0000 (Fri, 06 Oct 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-09-06 20:31:00 +0000 (Wed, 06 Sep 2023)");

  script_name("Ubuntu: Security Advisory (USN-6401-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(18\.04\ LTS|20\.04\ LTS|22\.04\ LTS|23\.04)");

  script_xref(name:"Advisory-ID", value:"USN-6401-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6401-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'freerdp2' package(s) announced via the USN-6401-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that FreeRDP did not properly manage certain inputs. A
malicious server could use this issue to cause FreeRDP clients to crash,
resulting in a denial of service, or possibly obtain sensitive
information. (CVE-2023-39350, CVE-2023-39351, CVE-2023-39353,
CVE-2023-39354, CVE-2023-40181, CVE-2023-40188, CVE-2023-40589)

It was discovered that FreeRDP did not properly manage certain inputs. A
malicious server could use this issue to cause FreeRDP clients to crash,
resulting in a denial of service, or possibly execute arbitrary code.
(CVE-2023-40186, CVE-2023-40567, CVE-2023-40569)");

  script_tag(name:"affected", value:"'freerdp2' package(s) on Ubuntu 18.04, Ubuntu 20.04, Ubuntu 22.04, Ubuntu 23.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libfreerdp2-2", ver:"2.2.0+dfsg1-0ubuntu0.18.04.4+esm1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libwinpr2-2", ver:"2.2.0+dfsg1-0ubuntu0.18.04.4+esm1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libwinpr2-dev", ver:"2.2.0+dfsg1-0ubuntu0.18.04.4+esm1", rls:"UBUNTU18.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libfreerdp2-2", ver:"2.2.0+dfsg1-0ubuntu0.20.04.5", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libwinpr2-2", ver:"2.2.0+dfsg1-0ubuntu0.20.04.5", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libwinpr2-dev", ver:"2.2.0+dfsg1-0ubuntu0.20.04.5", rls:"UBUNTU20.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libfreerdp2-2", ver:"2.6.1+dfsg1-3ubuntu2.4", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libwinpr2-2", ver:"2.6.1+dfsg1-3ubuntu2.4", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libwinpr2-dev", ver:"2.6.1+dfsg1-3ubuntu2.4", rls:"UBUNTU22.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libfreerdp2-2", ver:"2.10.0+dfsg1-1ubuntu0.2", rls:"UBUNTU23.04"))) {
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
