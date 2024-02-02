# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.1.1.2024.5608");
  script_cve_id("CVE-2024-0444");
  script_tag(name:"creation_date", value:"2024-01-29 04:19:07 +0000 (Mon, 29 Jan 2024)");
  script_version("2024-01-29T05:05:18+0000");
  script_tag(name:"last_modification", value:"2024-01-29 05:05:18 +0000 (Mon, 29 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Debian: Security Advisory (DSA-5608-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(11|12)");

  script_xref(name:"Advisory-ID", value:"DSA-5608-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2024/DSA-5608-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'gst-plugins-bad1.0' package(s) announced via the DSA-5608-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"affected", value:"'gst-plugins-bad1.0' package(s) on Debian 11, Debian 12.");

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

  if(!isnull(res = isdpkgvuln(pkg:"gir1.2-gst-plugins-bad-1.0", ver:"1.18.4-3+deb11u4", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gstreamer1.0-opencv", ver:"1.18.4-3+deb11u4", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gstreamer1.0-plugins-bad", ver:"1.18.4-3+deb11u4", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gstreamer1.0-plugins-bad-apps", ver:"1.18.4-3+deb11u4", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gstreamer1.0-wpe", ver:"1.18.4-3+deb11u4", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgstreamer-opencv1.0-0", ver:"1.18.4-3+deb11u4", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgstreamer-plugins-bad1.0-0", ver:"1.18.4-3+deb11u4", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgstreamer-plugins-bad1.0-dev", ver:"1.18.4-3+deb11u4", rls:"DEB11"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"gir1.2-gst-plugins-bad-1.0", ver:"1.22.0-4+deb12u5", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gstreamer1.0-opencv", ver:"1.22.0-4+deb12u5", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gstreamer1.0-plugins-bad", ver:"1.22.0-4+deb12u5", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gstreamer1.0-plugins-bad-apps", ver:"1.22.0-4+deb12u5", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gstreamer1.0-wpe", ver:"1.22.0-4+deb12u5", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgstreamer-opencv1.0-0", ver:"1.22.0-4+deb12u5", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgstreamer-plugins-bad1.0-0", ver:"1.22.0-4+deb12u5", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgstreamer-plugins-bad1.0-dev", ver:"1.22.0-4+deb12u5", rls:"DEB12"))) {
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
