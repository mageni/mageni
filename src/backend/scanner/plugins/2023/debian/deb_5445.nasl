# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.1.1.2023.5445");
  script_tag(name:"creation_date", value:"2023-07-03 04:21:43 +0000 (Mon, 03 Jul 2023)");
  script_version("2023-07-04T05:05:35+0000");
  script_tag(name:"last_modification", value:"2023-07-04 05:05:35 +0000 (Tue, 04 Jul 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Debian: Security Advisory (DSA-5445)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(11|12)");

  script_xref(name:"Advisory-ID", value:"DSA-5445");
  script_xref(name:"URL", value:"https://www.debian.org/security/2023/dsa-5445");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-5445");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/gst-plugins-good1.0");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'gst-plugins-good1.0' package(s) announced via the DSA-5445 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple multiple vulnerabilities were discovered in plugins for the GStreamer media framework and its codecs and demuxers, which may result in denial of service or potentially the execution of arbitrary code if a malformed media file is opened.

For the oldstable distribution (bullseye), this problem has been fixed in version 1.18.4-2+deb11u2.

For the stable distribution (bookworm), this problem has been fixed in version 1.22.0-5+deb12u1.

We recommend that you upgrade your gst-plugins-good1.0 packages.

For the detailed security status of gst-plugins-good1.0 please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'gst-plugins-good1.0' package(s) on Debian 11, Debian 12.");

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

  if(!isnull(res = isdpkgvuln(pkg:"gstreamer1.0-gtk3", ver:"1.18.4-2+deb11u2", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gstreamer1.0-plugins-good", ver:"1.18.4-2+deb11u2", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gstreamer1.0-pulseaudio", ver:"1.18.4-2+deb11u2", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gstreamer1.0-qt5", ver:"1.18.4-2+deb11u2", rls:"DEB11"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"gstreamer1.0-gtk3", ver:"1.22.0-5+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gstreamer1.0-plugins-good", ver:"1.22.0-5+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gstreamer1.0-pulseaudio", ver:"1.22.0-5+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gstreamer1.0-qt5", ver:"1.22.0-5+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gstreamer1.0-qt6", ver:"1.22.0-5+deb12u1", rls:"DEB12"))) {
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
