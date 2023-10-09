# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2023.6380.1");
  script_cve_id("CVE-2019-15604", "CVE-2019-15605", "CVE-2019-15606", "CVE-2020-8174", "CVE-2020-8265", "CVE-2020-8287");
  script_tag(name:"creation_date", value:"2023-09-20 04:08:41 +0000 (Wed, 20 Sep 2023)");
  script_version("2023-09-20T05:05:13+0000");
  script_tag(name:"last_modification", value:"2023-09-20 05:05:13 +0000 (Wed, 20 Sep 2023)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-07-20 23:15:00 +0000 (Tue, 20 Jul 2021)");

  script_name("Ubuntu: Security Advisory (USN-6380-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(16\.04\ LTS|18\.04\ LTS|20\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-6380-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6380-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'nodejs' package(s) announced via the USN-6380-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Rogier Schouten discovered that Node.js incorrectly handled certain inputs. If
a user or an automated system were tricked into opening a specially crafted
input file, a remote attacker could possibly use this issue to cause a denial
of service. This issue only affected Ubuntu 16.04 LTS and Ubuntu 18.04 LTS.
(CVE-2019-15604)

Ethan Rubinson discovered that Node.js incorrectly handled certain inputs. If
a user or an automated system were tricked into opening a specially crafted
input file, a remote attacker could possibly use this issue to obtain
sensitive information. This issue only affected Ubuntu 16.04 LTS and
Ubuntu 18.04 LTS. (CVE-2019-15605)

Alyssa Wilk discovered that Node.js incorrectly handled certain inputs. If a
user or an automated system were tricked into opening a specially crafted
input file, a remote attacker could possibly use this issue to execute
arbitrary code. This issue only affected Ubuntu 16.04 LTS and
Ubuntu 18.04 LTS. (CVE-2019-15606)

Tobias Niessen discovered that Node.js incorrectly handled certain inputs. If
a user or an automated system were tricked into opening a specially crafted
input file, a remote attacker could possibly use this issue to cause a
denial of service. This issue only affected Ubuntu 18.04 LTS and
Ubuntu 20.04 LTS. (CVE-2020-8174)

It was discovered that Node.js incorrectly handled certain inputs. If a user
or an automated system were tricked into opening a specially crafted input
file, a remote attacker could possibly use this issue to cause a
denial of service. (CVE-2020-8265, CVE-2020-8287)");

  script_tag(name:"affected", value:"'nodejs' package(s) on Ubuntu 16.04, Ubuntu 18.04, Ubuntu 20.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"nodejs", ver:"4.2.6~dfsg-1ubuntu4.2+esm2", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nodejs-dev", ver:"4.2.6~dfsg-1ubuntu4.2+esm2", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nodejs-legacy", ver:"4.2.6~dfsg-1ubuntu4.2+esm2", rls:"UBUNTU16.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"nodejs", ver:"8.10.0~dfsg-2ubuntu0.4+esm2", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nodejs-dev", ver:"8.10.0~dfsg-2ubuntu0.4+esm2", rls:"UBUNTU18.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libnode-dev", ver:"10.19.0~dfsg-3ubuntu1.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libnode64", ver:"10.19.0~dfsg-3ubuntu1.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nodejs", ver:"10.19.0~dfsg-3ubuntu1.1", rls:"UBUNTU20.04 LTS"))) {
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
