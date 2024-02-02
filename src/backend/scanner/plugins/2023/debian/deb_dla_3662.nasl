# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2023.3662");
  script_cve_id("CVE-2020-21427", "CVE-2020-21428", "CVE-2020-22524");
  script_tag(name:"creation_date", value:"2023-11-27 04:28:29 +0000 (Mon, 27 Nov 2023)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-08-24 21:57:26 +0000 (Thu, 24 Aug 2023)");

  script_name("Debian: Security Advisory (DLA-3662-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"Advisory-ID", value:"DLA-3662-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2023/DLA-3662-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/freeimage");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'freeimage' package(s) announced via the DLA-3662-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple vulnerabilities were discovered in freeimage, library for graphics image formats.

CVE-2020-21427 Buffer overflow vulnerability in function LoadPixelDataRLE8 in PluginBMP.cpp allows remote attackers to run arbitrary code and cause other impacts via crafted image file.

CVE-2020-21428 Buffer overflow vulnerability in function LoadRGB in PluginDDS.cpp allows remote attackers to run arbitrary code and cause other impacts via crafted image file.

CVE-2020-22524 Buffer overflow vulnerability in FreeImage_Load function allows remote attackers to run arbitrary code and cause other impacts via crafted PFM file.

For Debian 10 buster, these problems have been fixed in version 3.18.0+ds2-1+deb10u2.

We recommend that you upgrade your freeimage packages.

For the detailed security status of freeimage please refer to its security tracker page at: [link moved to references]

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'freeimage' package(s) on Debian 10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libfreeimage-dev", ver:"3.18.0+ds2-1+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libfreeimage3", ver:"3.18.0+ds2-1+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libfreeimageplus-dev", ver:"3.18.0+ds2-1+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libfreeimageplus-doc", ver:"3.18.0+ds2-1+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libfreeimageplus3", ver:"3.18.0+ds2-1+deb10u2", rls:"DEB10"))) {
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
