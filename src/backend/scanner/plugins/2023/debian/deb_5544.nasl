# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.1.1.2023.5544");
  script_cve_id("CVE-2023-44981");
  script_tag(name:"creation_date", value:"2023-11-01 04:20:26 +0000 (Wed, 01 Nov 2023)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"9.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-10-18 19:55:37 +0000 (Wed, 18 Oct 2023)");

  script_name("Debian: Security Advisory (DSA-5544-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(11|12)");

  script_xref(name:"Advisory-ID", value:"DSA-5544-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2023/DSA-5544-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-5544");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/zookeeper");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'zookeeper' package(s) announced via the DSA-5544-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Damien Diederen discovered that SASL quorum peer authentication within Zookeeper, a service for maintaining configuration information, was insufficiently enforced in some configurations.

For the oldstable distribution (bullseye), this problem has been fixed in version 3.4.13-6+deb11u1.

For the stable distribution (bookworm), this problem has been fixed in version 3.8.0-11+deb12u1.

We recommend that you upgrade your zookeeper packages.

For the detailed security status of zookeeper please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'zookeeper' package(s) on Debian 11, Debian 12.");

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

if(release == "DEB11") {

  if(!isnull(res = isdpkgvuln(pkg:"libzookeeper-java", ver:"3.4.13-6+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libzookeeper-java-doc", ver:"3.4.13-6+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libzookeeper-mt-dev", ver:"3.4.13-6+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libzookeeper-mt2", ver:"3.4.13-6+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libzookeeper-st-dev", ver:"3.4.13-6+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libzookeeper-st2", ver:"3.4.13-6+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3-zookeeper", ver:"3.4.13-6+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"zookeeper", ver:"3.4.13-6+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"zookeeper-bin", ver:"3.4.13-6+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"zookeeperd", ver:"3.4.13-6+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "DEB12") {

  if(!isnull(res = isdpkgvuln(pkg:"libzookeeper-java", ver:"3.8.0-11+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libzookeeper-java-doc", ver:"3.8.0-11+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libzookeeper-mt-dev", ver:"3.8.0-11+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libzookeeper-mt2", ver:"3.8.0-11+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libzookeeper-st-dev", ver:"3.8.0-11+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libzookeeper-st2", ver:"3.8.0-11+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3-zookeeper", ver:"3.8.0-11+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"zookeeper", ver:"3.8.0-11+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"zookeeper-bin", ver:"3.8.0-11+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"zookeeperd", ver:"3.8.0-11+deb12u1", rls:"DEB12"))) {
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
