# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2023.5807.3");
  script_cve_id("CVE-2022-46285");
  script_tag(name:"creation_date", value:"2023-07-27 04:09:33 +0000 (Thu, 27 Jul 2023)");
  script_version("2023-07-27T05:05:08+0000");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-02-16 14:09:00 +0000 (Thu, 16 Feb 2023)");

  script_name("Ubuntu: Security Advisory (USN-5807-3)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU14\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-5807-3");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5807-3");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libxpm' package(s) announced via the USN-5807-3 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-5807-1 fixed a vulnerability in libXpm. This update provides
the corresponding update for Ubuntu 14.04 ESM.

Original advisory details:

 Marco Ivaldi discovered that libXpm incorrectly handled certain XPM files.
 If a user or automated system were tricked into opening a specially crafted
 XPM file, a remote attacker could possibly use this issue to cause libXpm
 to stop responding, resulting in a denial of service. (CVE-2022-46285)");

  script_tag(name:"affected", value:"'libxpm' package(s) on Ubuntu 14.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libxpm4", ver:"1:3.5.10-1ubuntu0.1+esm1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xpmutils", ver:"1:3.5.10-1ubuntu0.1+esm1", rls:"UBUNTU14.04 LTS"))) {
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
