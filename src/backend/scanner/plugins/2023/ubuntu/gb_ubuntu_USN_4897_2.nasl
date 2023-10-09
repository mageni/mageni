# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2023.4897.2");
  script_cve_id("CVE-2021-20270", "CVE-2021-27291");
  script_tag(name:"creation_date", value:"2023-08-14 14:23:41 +0000 (Mon, 14 Aug 2023)");
  script_version("2023-08-15T05:05:29+0000");
  script_tag(name:"last_modification", value:"2023-08-15 05:05:29 +0000 (Tue, 15 Aug 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-05-06 23:15:00 +0000 (Thu, 06 May 2021)");

  script_name("Ubuntu: Security Advisory (USN-4897-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU14\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-4897-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4897-2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'pygments' package(s) announced via the USN-4897-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-4897-1 fixed several vulnerabilities in Pygments. This update provides
the corresponding update for Ubuntu 14.04 LTS.

Original advisory details:

 Ben Caller discovered that Pygments incorrectly handled parsing certain
 files. If a user or automated system were tricked into parsing a specially
 crafted file, a remote attacker could cause Pygments to hang or consume
 resources, resulting in a denial of service. (CVE-2021-27291)

 It was discovered that Pygments incorrectly handled parsing certain
 files. An attacker could possibly use this issue to cause a denial of
 service. (CVE-2021-20270)");

  script_tag(name:"affected", value:"'pygments' package(s) on Ubuntu 14.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"python-pygments", ver:"1.6+dfsg-1ubuntu1.1+esm1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3-pygments", ver:"1.6+dfsg-1ubuntu1.1+esm1", rls:"UBUNTU14.04 LTS"))) {
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
