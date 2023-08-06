# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2023.3513");
  script_cve_id("CVE-2023-25433", "CVE-2023-26965", "CVE-2023-26966", "CVE-2023-2908", "CVE-2023-3316", "CVE-2023-3618", "CVE-2023-38288", "CVE-2023-38289");
  script_tag(name:"creation_date", value:"2023-08-01 04:25:26 +0000 (Tue, 01 Aug 2023)");
  script_version("2023-08-01T13:29:10+0000");
  script_tag(name:"last_modification", value:"2023-08-01 13:29:10 +0000 (Tue, 01 Aug 2023)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-07-20 17:16:00 +0000 (Thu, 20 Jul 2023)");

  script_name("Debian: Security Advisory (DLA-3513)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"Advisory-ID", value:"DLA-3513");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2023/dla-3513");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/tiff");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'tiff' package(s) announced via the DLA-3513 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple vulnerabilities were found in tiff, a library and tools providing support for the Tag Image File Format (TIFF).

CVE-2023-2908

NULL pointer dereference in tif_dir.c

CVE-2023-3316

NULL pointer dereference in TIFFClose()

CVE-2023-3618

Buffer overflow in tiffcrop

CVE-2023-25433

Buffer overflow in tiffcrop

CVE-2023-26965

Use after free in tiffcrop

CVE-2023-26966

Buffer overflow in uv_encode()

CVE-2023-38288

Integer overflow in tiffcp

CVE-2023-38289

Integer overflow in raw2tiff

For Debian 10 buster, these problems have been fixed in version 4.1.0+git191117-2~deb10u8.

We recommend that you upgrade your tiff packages.

For the detailed security status of tiff please refer to its security tracker page at: [link moved to references]

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'tiff' package(s) on Debian 10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libtiff-dev", ver:"4.1.0+git191117-2~deb10u8", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libtiff-doc", ver:"4.1.0+git191117-2~deb10u8", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libtiff-opengl", ver:"4.1.0+git191117-2~deb10u8", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libtiff-tools", ver:"4.1.0+git191117-2~deb10u8", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libtiff5", ver:"4.1.0+git191117-2~deb10u8", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libtiff5-dev", ver:"4.1.0+git191117-2~deb10u8", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libtiffxx5", ver:"4.1.0+git191117-2~deb10u8", rls:"DEB10"))) {
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
