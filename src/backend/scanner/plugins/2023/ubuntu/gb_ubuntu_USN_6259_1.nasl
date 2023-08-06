# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2023.6259.1");
  script_cve_id("CVE-2020-13987", "CVE-2020-13988", "CVE-2020-17437");
  script_tag(name:"creation_date", value:"2023-07-28 04:09:30 +0000 (Fri, 28 Jul 2023)");
  script_version("2023-07-28T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-07-28 05:05:23 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-03-09 15:15:00 +0000 (Tue, 09 Mar 2021)");

  script_name("Ubuntu: Security Advisory (USN-6259-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(16\.04\ LTS|18\.04\ LTS|20\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-6259-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6259-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'open-iscsi' package(s) announced via the USN-6259-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Jos Wetzels, Stanislav Dashevskyi, and Amine Amri discovered that
Open-iSCSI incorrectly handled certain checksums for IP packets.
An attacker could possibly use this issue to expose sensitive information.
(CVE-2020-13987)

Jos Wetzels, Stanislav Dashevskyi, Amine Amri discovered that
Open-iSCSI incorrectly handled certain parsing TCP MSS options.
An attacker could possibly use this issue to cause a crash or cause
unexpected behavior. (CVE-2020-13988)

Amine Amri and Stanislav Dashevskyi discovered that Open-iSCSI
incorrectly handled certain TCP data. An attacker could possibly
use this issue to expose sensitive information. (CVE-2020-17437)");

  script_tag(name:"affected", value:"'open-iscsi' package(s) on Ubuntu 16.04, Ubuntu 18.04, Ubuntu 20.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"open-iscsi", ver:"2.0.873+git0.3b4b4500-14ubuntu3.7+esm1", rls:"UBUNTU16.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"open-iscsi", ver:"2.0.874-5ubuntu2.11+esm1", rls:"UBUNTU18.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"open-iscsi", ver:"2.0.874-7.1ubuntu6.4", rls:"UBUNTU20.04 LTS"))) {
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
