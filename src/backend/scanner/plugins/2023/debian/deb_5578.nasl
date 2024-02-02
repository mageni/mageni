# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.1.1.2023.5578");
  script_cve_id("CVE-2023-46751");
  script_tag(name:"creation_date", value:"2023-12-18 04:20:34 +0000 (Mon, 18 Dec 2023)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-12-09 04:52:20 +0000 (Sat, 09 Dec 2023)");

  script_name("Debian: Security Advisory (DSA-5578-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB12");

  script_xref(name:"Advisory-ID", value:"DSA-5578-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2023/DSA-5578-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-5578");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/ghostscript");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'ghostscript' package(s) announced via the DSA-5578-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that Ghostscript, the GPL PostScript/PDF interpreter, does not properly handle errors in the gdev_prn_open_printer_seekable() function, which could result in the execution of arbitrary commands if malformed document files are processed.

For the stable distribution (bookworm), this problem has been fixed in version 10.0.0~dfsg-11+deb12u3.

We recommend that you upgrade your ghostscript packages.

For the detailed security status of ghostscript please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'ghostscript' package(s) on Debian 12.");

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

if(release == "DEB12") {

  if(!isnull(res = isdpkgvuln(pkg:"ghostscript", ver:"10.0.0~dfsg-11+deb12u3", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ghostscript-doc", ver:"10.0.0~dfsg-11+deb12u3", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ghostscript-x", ver:"10.0.0~dfsg-11+deb12u3", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgs-common", ver:"10.0.0~dfsg-11+deb12u3", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgs-dev", ver:"10.0.0~dfsg-11+deb12u3", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgs10", ver:"10.0.0~dfsg-11+deb12u3", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgs10-common", ver:"10.0.0~dfsg-11+deb12u3", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgs9-common", ver:"10.0.0~dfsg-11+deb12u3", rls:"DEB12"))) {
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
