# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2023.3562");
  script_cve_id("CVE-2023-33466");
  script_tag(name:"creation_date", value:"2023-09-13 04:19:35 +0000 (Wed, 13 Sep 2023)");
  script_version("2023-09-13T05:05:22+0000");
  script_tag(name:"last_modification", value:"2023-09-13 05:05:22 +0000 (Wed, 13 Sep 2023)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-07-06 18:24:00 +0000 (Thu, 06 Jul 2023)");

  script_name("Debian: Security Advisory (DLA-3562)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"Advisory-ID", value:"DLA-3562");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2023/dla-3562");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/orthanc");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'orthanc' package(s) announced via the DLA-3562 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A security vulnerability was identified in Orthanc, a DICOM server used for medical imaging, whereby authenticated API users had the capability to overwrite arbitrary files and, in certain configurations, execute unauthorized code.

This update addresses the issue by backporting a safeguard mechanism: the RestApiWriteToFileSystemEnabled option is now included, and it is set to true by default in the /etc/orthanc/orthanc.json configuration file. Should users wish to revert to the previous behavior, they can manually set this option to true themselves.

For Debian 10 buster, this problem has been fixed in version 1.5.6+dfsg-1+deb10u1.

We recommend that you upgrade your orthanc packages.

For the detailed security status of orthanc please refer to its security tracker page at: [link moved to references]

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'orthanc' package(s) on Debian 10.");

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

if(release == "DEB10") {

  if(!isnull(res = isdpkgvuln(pkg:"orthanc", ver:"1.5.6+dfsg-1+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"orthanc-dev", ver:"1.5.6+dfsg-1+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"orthanc-doc", ver:"1.5.6+dfsg-1+deb10u1", rls:"DEB10"))) {
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
