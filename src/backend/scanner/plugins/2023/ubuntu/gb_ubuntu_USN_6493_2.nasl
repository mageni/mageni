# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2023.6493.2");
  script_tag(name:"creation_date", value:"2023-11-22 04:08:57 +0000 (Wed, 22 Nov 2023)");
  script_version("2023-11-22T05:05:24+0000");
  script_tag(name:"last_modification", value:"2023-11-22 05:05:24 +0000 (Wed, 22 Nov 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-6493-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(16\.04\ LTS|18\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-6493-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6493-2");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/2043739");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'hibagent' package(s) announced via the USN-6493-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-6493-1 fixed a vulnerability in hibagent. This update provides
the corresponding update for Ubuntu 16.04 LTS and Ubuntu 18.04 LTS.

Original advisory details:

 On Ubuntu 18.04 LTS and Ubuntu 16.04 LTS, the hibagent package has been
 updated to add IMDSv2 support, as IMDSv1 uses an insecure protocol and is
 no longer recommended.

 In addition, on all releases, hibagent has been updated to do nothing if
 ODH is configured.");

  script_tag(name:"affected", value:"'hibagent' package(s) on Ubuntu 16.04, Ubuntu 18.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"hibagent", ver:"1.0.1-0ubuntu1~16.04.1+esm1", rls:"UBUNTU16.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"hibagent", ver:"1.0.1-0ubuntu1.18.04.1+esm1", rls:"UBUNTU18.04 LTS"))) {
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
