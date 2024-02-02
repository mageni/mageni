# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2023.3676");
  script_cve_id("CVE-2023-27102", "CVE-2023-27103", "CVE-2023-43887", "CVE-2023-47471");
  script_tag(name:"creation_date", value:"2023-12-01 04:21:28 +0000 (Fri, 01 Dec 2023)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-03-17 19:28:38 +0000 (Fri, 17 Mar 2023)");

  script_name("Debian: Security Advisory (DLA-3676-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"Advisory-ID", value:"DLA-3676-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2023/DLA-3676-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/libde265");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'libde265' package(s) announced via the DLA-3676-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple issues were found in libde265, an open source implementation of the h.265 video codec.

CVE-2023-27102

NULL pointer dereference in function decoder_context::process_slice_segment_header at decctx.cc.

CVE-2023-27103

Heap buffer overflow via the function derive_collocated_motion_vectors at motion.cc.

CVE-2023-43887

Multiple buffer overflows via the num_tile_columns and num_tile_row parameters in the function pic_parameter_set::dump.

CVE-2023-47471

Buffer overflow vulnerability in strukturag may cause a denial of service via the slice_segment_header function in the slice.cc component.

For Debian 10 buster, these problems have been fixed in version 1.0.11-0+deb10u5.

We recommend that you upgrade your libde265 packages.

For the detailed security status of libde265 please refer to its security tracker page at: [link moved to references]

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'libde265' package(s) on Debian 10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libde265-0", ver:"1.0.11-0+deb10u5", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libde265-dev", ver:"1.0.11-0+deb10u5", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libde265-examples", ver:"1.0.11-0+deb10u5", rls:"DEB10"))) {
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
