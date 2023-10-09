# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.1.1.2023.5473");
  script_cve_id("CVE-2023-33466");
  script_tag(name:"creation_date", value:"2023-08-10 04:30:03 +0000 (Thu, 10 Aug 2023)");
  script_version("2023-08-11T05:05:41+0000");
  script_tag(name:"last_modification", value:"2023-08-11 05:05:41 +0000 (Fri, 11 Aug 2023)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-07-06 18:24:00 +0000 (Thu, 06 Jul 2023)");

  script_name("Debian: Security Advisory (DSA-5473)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(11|12)");

  script_xref(name:"Advisory-ID", value:"DSA-5473");
  script_xref(name:"URL", value:"https://www.debian.org/security/2023/dsa-5473");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-5473");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/orthanc");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'orthanc' package(s) announced via the DSA-5473 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that authenticated API users of Orthanc, a DICOM server for medical imaging, could overwrite arbitrary files and in some setups execute arbitrary code.

This update backports the option RestApiWriteToFileSystemEnabled, setting it to true in /etc/orthanc/orthanc.json restores the previous behaviour.

For the oldstable distribution (bullseye), this problem has been fixed in version 1.9.2+really1.9.1+dfsg-1+deb11u1.

For the stable distribution (bookworm), this problem has been fixed in version 1.10.1+dfsg-2+deb12u1.

We recommend that you upgrade your orthanc packages.

For the detailed security status of orthanc please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'orthanc' package(s) on Debian 11, Debian 12.");

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

  if(!isnull(res = isdpkgvuln(pkg:"liborthancframework-dev", ver:"1.9.2+really1.9.1+dfsg-1+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"liborthancframework1", ver:"1.9.2+really1.9.1+dfsg-1+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"orthanc", ver:"1.9.2+really1.9.1+dfsg-1+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"orthanc-dev", ver:"1.9.2+really1.9.1+dfsg-1+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"orthanc-doc", ver:"1.9.2+really1.9.1+dfsg-1+deb11u1", rls:"DEB11"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"liborthancframework-dev", ver:"1.10.1+dfsg-2+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"liborthancframework1", ver:"1.10.1+dfsg-2+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"orthanc", ver:"1.10.1+dfsg-2+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"orthanc-dev", ver:"1.10.1+dfsg-2+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"orthanc-doc", ver:"1.10.1+dfsg-2+deb12u1", rls:"DEB12"))) {
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
