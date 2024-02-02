# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2023.6491.1");
  script_cve_id("CVE-2022-32212", "CVE-2022-32213", "CVE-2022-32214", "CVE-2022-32215", "CVE-2022-35256", "CVE-2022-43548");
  script_tag(name:"creation_date", value:"2023-11-22 04:08:57 +0000 (Wed, 22 Nov 2023)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-12-08 16:02:51 +0000 (Thu, 08 Dec 2022)");

  script_name("Ubuntu: Security Advisory (USN-6491-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(18\.04\ LTS|20\.04\ LTS|22\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-6491-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6491-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'nodejs' package(s) announced via the USN-6491-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Axel Chong discovered that Node.js incorrectly handled certain inputs. If a
user or an automated system were tricked into opening a specially crafted
input file, a remote attacker could possibly use this issue to execute
arbitrary code. (CVE-2022-32212)

Zeyu Zhang discovered that Node.js incorrectly handled certain inputs. If a
user or an automated system were tricked into opening a specially crafted
input file, a remote attacker could possibly use this issue to execute
arbitrary code. This issue only affected Ubuntu 22.04 LTS. (CVE-2022-32213,
CVE-2022-32214, CVE-2022-32215)

It was discovered that Node.js incorrectly handled certain inputs. If a user
or an automated system were tricked into opening a specially crafted input
file, a remote attacker could possibly use this issue to execute arbitrary
code. This issue only affected Ubuntu 22.04 LTS. (CVE-2022-35256)

It was discovered that Node.js incorrectly handled certain inputs. If a user
or an automated system were tricked into opening a specially crafted input
file, a remote attacker could possibly use this issue to execute arbitrary
code. This issue only affected Ubuntu 22.04 LTS. (CVE-2022-43548)");

  script_tag(name:"affected", value:"'nodejs' package(s) on Ubuntu 18.04, Ubuntu 20.04, Ubuntu 22.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"nodejs", ver:"8.10.0~dfsg-2ubuntu0.4+esm4", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nodejs-dev", ver:"8.10.0~dfsg-2ubuntu0.4+esm4", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nodejs-doc", ver:"8.10.0~dfsg-2ubuntu0.4+esm4", rls:"UBUNTU18.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libnode-dev", ver:"10.19.0~dfsg-3ubuntu1.3", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libnode64", ver:"10.19.0~dfsg-3ubuntu1.3", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nodejs", ver:"10.19.0~dfsg-3ubuntu1.3", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nodejs-doc", ver:"10.19.0~dfsg-3ubuntu1.3", rls:"UBUNTU20.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libnode-dev", ver:"12.22.9~dfsg-1ubuntu3.2", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libnode72", ver:"12.22.9~dfsg-1ubuntu3.2", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nodejs", ver:"12.22.9~dfsg-1ubuntu3.2", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nodejs-doc", ver:"12.22.9~dfsg-1ubuntu3.2", rls:"UBUNTU22.04 LTS"))) {
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
