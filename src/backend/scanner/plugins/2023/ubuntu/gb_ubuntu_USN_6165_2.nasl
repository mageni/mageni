# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2023.6165.2");
  script_cve_id("CVE-2023-29499", "CVE-2023-32611", "CVE-2023-32636", "CVE-2023-32643", "CVE-2023-32665");
  script_tag(name:"creation_date", value:"2023-10-20 04:08:37 +0000 (Fri, 20 Oct 2023)");
  script_version("2023-10-20T05:06:03+0000");
  script_tag(name:"last_modification", value:"2023-10-20 05:06:03 +0000 (Fri, 20 Oct 2023)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-09-20 14:32:00 +0000 (Wed, 20 Sep 2023)");

  script_name("Ubuntu: Security Advisory (USN-6165-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.04\ LTS|16\.04\ LTS|18\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-6165-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6165-2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'glib2.0' package(s) announced via the USN-6165-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-6165-1 fixed vulnerabilities in GLib. This update provides the
corresponding updates for Ubuntu 14.04 LTS, Ubuntu 16.04 LTS and Ubuntu
18.04 LTS.

Original advisory details:

 It was discovered that GLib incorrectly handled non-normal GVariants. An
 attacker could use this issue to cause GLib to crash, resulting in a
 denial of service, or perform other unknown attacks.");

  script_tag(name:"affected", value:"'glib2.0' package(s) on Ubuntu 14.04, Ubuntu 16.04, Ubuntu 18.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libglib2.0-0", ver:"2.40.2-0ubuntu1.1+esm6", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libglib2.0-bin", ver:"2.40.2-0ubuntu1.1+esm6", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU16.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"libglib2.0-0", ver:"2.48.2-0ubuntu4.8+esm3", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libglib2.0-bin", ver:"2.48.2-0ubuntu4.8+esm3", rls:"UBUNTU16.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libglib2.0-0", ver:"2.56.4-0ubuntu0.18.04.9+esm3", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libglib2.0-bin", ver:"2.56.4-0ubuntu0.18.04.9+esm3", rls:"UBUNTU18.04 LTS"))) {
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
