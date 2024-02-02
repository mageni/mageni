# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2023.6463.2");
  script_cve_id("CVE-2023-34058", "CVE-2023-34059");
  script_tag(name:"creation_date", value:"2023-12-07 04:08:46 +0000 (Thu, 07 Dec 2023)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:H/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:A/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-11-07 21:07:45 +0000 (Tue, 07 Nov 2023)");

  script_name("Ubuntu: Security Advisory (USN-6463-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(16\.04\ LTS|18\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-6463-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6463-2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'open-vm-tools' package(s) announced via the USN-6463-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-6463-1 fixed vulnerabilities in Open VM Tools. This update provides
the corresponding updates for Ubuntu 16.04 LTS and Ubuntu 18.04 LTS.

Original advisory details:

 It was discovered that Open VM Tools incorrectly handled SAML tokens. A
 remote attacker with Guest Operations privileges could possibly use this
 issue to elevate their privileges. (CVE-2023-34058)

 Matthias Gerstner discovered that Open VM Tools incorrectly handled file
 descriptors when dropping privileges. A local attacker could possibly use
 this issue to hijack /dev/uinput and simulate user inputs. (CVE-2023-34059)");

  script_tag(name:"affected", value:"'open-vm-tools' package(s) on Ubuntu 16.04, Ubuntu 18.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"open-vm-tools", ver:"2:10.2.0-3~ubuntu0.16.04.1+esm4", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"open-vm-tools-desktop", ver:"2:10.2.0-3~ubuntu0.16.04.1+esm4", rls:"UBUNTU16.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"open-vm-tools", ver:"2:11.0.5-4ubuntu0.18.04.3+esm3", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"open-vm-tools-desktop", ver:"2:11.0.5-4ubuntu0.18.04.3+esm3", rls:"UBUNTU18.04 LTS"))) {
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
