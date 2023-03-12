# Copyright (C) 2023 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.1.1.2007.1294");
  script_cve_id("CVE-2007-1003", "CVE-2007-1351", "CVE-2007-1352", "CVE-2007-1667");
  script_tag(name:"creation_date", value:"2023-03-08 12:56:44 +0000 (Wed, 08 Mar 2023)");
  script_version("2023-03-09T10:09:19+0000");
  script_tag(name:"last_modification", value:"2023-03-09 10:09:19 +0000 (Thu, 09 Mar 2023)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-1294)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB3\.1");

  script_xref(name:"Advisory-ID", value:"DSA-1294");
  script_xref(name:"URL", value:"https://www.debian.org/security/2007/dsa-1294");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'xfree86' package(s) announced via the DSA-1294 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the X Window System, which may lead to privilege escalation. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2007-1003

Sean Larsson discovered an integer overflow in the XC-MISC extension, which might lead to denial of service or local privilege escalation.

CVE-2007-1351

Greg MacManus discovered an integer overflow in the font handling, which might lead to denial of service or local privilege escalation.

CVE-2007-1352

Greg MacManus discovered an integer overflow in the font handling, which might lead to denial of service or local privilege escalation.

CVE-2007-1667

Sami Leides discovered an integer overflow in the libx11 library which might lead to the execution of arbitrary code. This update introduces tighter sanity checking of input passed to XCreateImage(). To cope with this an updated rdesktop package is delivered along with this security update. Another application reported to break is the proprietary Opera browser, which isn't part of Debian. The vendor has released updated packages, though.

For the old stable distribution (sarge) these problems have been fixed in version 4.3.0.dfsg.1-14sarge4. This update lacks builds for the Sparc architecture, due to problems on the build host. Packages will be released once this problem has been resolved.

The stable distribution (etch) isn't affected by these problems, as the vulnerabilities have already been fixed during the Etch preparation freeze phase.

We recommend that you upgrade your XFree86 packages.");

  script_tag(name:"affected", value:"'xfree86' package(s) on Debian 3.1.");

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

if(release == "DEB3.1") {

  if(!isnull(res = isdpkgvuln(pkg:"lbxproxy", ver:"4.3.0.dfsg.1-14sarge4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libdps-dev", ver:"4.3.0.dfsg.1-14sarge4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libdps1-dbg", ver:"4.3.0.dfsg.1-14sarge4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libdps1", ver:"4.3.0.dfsg.1-14sarge4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libice-dev", ver:"4.3.0.dfsg.1-14sarge4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libice6-dbg", ver:"4.3.0.dfsg.1-14sarge4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libice6", ver:"4.3.0.dfsg.1-14sarge4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libsm-dev", ver:"4.3.0.dfsg.1-14sarge4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libsm6-dbg", ver:"4.3.0.dfsg.1-14sarge4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libsm6", ver:"4.3.0.dfsg.1-14sarge4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libx11-6-dbg", ver:"4.3.0.dfsg.1-14sarge4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libx11-6", ver:"4.3.0.dfsg.1-14sarge4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libx11-dev", ver:"4.3.0.dfsg.1-14sarge4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxaw6-dbg", ver:"4.3.0.dfsg.1-14sarge4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxaw6-dev", ver:"4.3.0.dfsg.1-14sarge4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxaw6", ver:"4.3.0.dfsg.1-14sarge4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxaw7-dbg", ver:"4.3.0.dfsg.1-14sarge4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxaw7-dev", ver:"4.3.0.dfsg.1-14sarge4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxaw7", ver:"4.3.0.dfsg.1-14sarge4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxext-dev", ver:"4.3.0.dfsg.1-14sarge4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxext6-dbg", ver:"4.3.0.dfsg.1-14sarge4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxext6", ver:"4.3.0.dfsg.1-14sarge4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxft1-dbg", ver:"4.3.0.dfsg.1-14sarge4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxft1", ver:"4.3.0.dfsg.1-14sarge4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxi-dev", ver:"4.3.0.dfsg.1-14sarge4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxi6-dbg", ver:"4.3.0.dfsg.1-14sarge4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxi6", ver:"4.3.0.dfsg.1-14sarge4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxmu-dev", ver:"4.3.0.dfsg.1-14sarge4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxmu6-dbg", ver:"4.3.0.dfsg.1-14sarge4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxmu6", ver:"4.3.0.dfsg.1-14sarge4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxmuu-dev", ver:"4.3.0.dfsg.1-14sarge4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxmuu1-dbg", ver:"4.3.0.dfsg.1-14sarge4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxmuu1", ver:"4.3.0.dfsg.1-14sarge4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxp-dev", ver:"4.3.0.dfsg.1-14sarge4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxp6-dbg", ver:"4.3.0.dfsg.1-14sarge4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxp6", ver:"4.3.0.dfsg.1-14sarge4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxpm-dev", ver:"4.3.0.dfsg.1-14sarge4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxpm4-dbg", ver:"4.3.0.dfsg.1-14sarge4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxpm4", ver:"4.3.0.dfsg.1-14sarge4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxrandr-dev", ver:"4.3.0.dfsg.1-14sarge4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxrandr2-dbg", ver:"4.3.0.dfsg.1-14sarge4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxrandr2", ver:"4.3.0.dfsg.1-14sarge4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxt-dev", ver:"4.3.0.dfsg.1-14sarge4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxt6-dbg", ver:"4.3.0.dfsg.1-14sarge4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxt6", ver:"4.3.0.dfsg.1-14sarge4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxtrap-dev", ver:"4.3.0.dfsg.1-14sarge4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxtrap6-dbg", ver:"4.3.0.dfsg.1-14sarge4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxtrap6", ver:"4.3.0.dfsg.1-14sarge4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxtst-dev", ver:"4.3.0.dfsg.1-14sarge4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxtst6-dbg", ver:"4.3.0.dfsg.1-14sarge4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxtst6", ver:"4.3.0.dfsg.1-14sarge4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxv-dev", ver:"4.3.0.dfsg.1-14sarge4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxv1-dbg", ver:"4.3.0.dfsg.1-14sarge4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxv1", ver:"4.3.0.dfsg.1-14sarge4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pm-dev", ver:"4.3.0.dfsg.1-14sarge4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"proxymngr", ver:"4.3.0.dfsg.1-14sarge4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"twm", ver:"4.3.0.dfsg.1-14sarge4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"x-dev", ver:"4.3.0.dfsg.1-14sarge4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"x-window-system-core", ver:"4.3.0.dfsg.1-14sarge4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"x-window-system-dev", ver:"4.3.0.dfsg.1-14sarge4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"x-window-system", ver:"4.3.0.dfsg.1-14sarge4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xbase-clients", ver:"4.3.0.dfsg.1-14sarge4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xdm", ver:"4.3.0.dfsg.1-14sarge4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xfonts-100dpi-transcoded", ver:"4.3.0.dfsg.1-14sarge4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xfonts-100dpi", ver:"4.3.0.dfsg.1-14sarge4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xfonts-75dpi-transcoded", ver:"4.3.0.dfsg.1-14sarge4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xfonts-75dpi", ver:"4.3.0.dfsg.1-14sarge4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xfonts-base-transcoded", ver:"4.3.0.dfsg.1-14sarge4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xfonts-base", ver:"4.3.0.dfsg.1-14sarge4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xfonts-cyrillic", ver:"4.3.0.dfsg.1-14sarge4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xfonts-scalable", ver:"4.3.0.dfsg.1-14sarge4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xfree86-common", ver:"4.3.0.dfsg.1-14sarge4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xfs", ver:"4.3.0.dfsg.1-14sarge4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xfwp", ver:"4.3.0.dfsg.1-14sarge4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xlibmesa-dev", ver:"4.3.0.dfsg.1-14sarge4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xlibmesa-dri-dbg", ver:"4.3.0.dfsg.1-14sarge4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xlibmesa-dri", ver:"4.3.0.dfsg.1-14sarge4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xlibmesa-gl-dbg", ver:"4.3.0.dfsg.1-14sarge4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xlibmesa-gl-dev", ver:"4.3.0.dfsg.1-14sarge4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xlibmesa-gl", ver:"4.3.0.dfsg.1-14sarge4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xlibmesa-glu-dbg", ver:"4.3.0.dfsg.1-14sarge4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xlibmesa-glu-dev", ver:"4.3.0.dfsg.1-14sarge4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xlibmesa-glu", ver:"4.3.0.dfsg.1-14sarge4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xlibmesa3-dbg", ver:"4.3.0.dfsg.1-14sarge4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xlibmesa3", ver:"4.3.0.dfsg.1-14sarge4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xlibosmesa-dev", ver:"4.3.0.dfsg.1-14sarge4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xlibosmesa4-dbg", ver:"4.3.0.dfsg.1-14sarge4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xlibosmesa4", ver:"4.3.0.dfsg.1-14sarge4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xlibs-data", ver:"4.3.0.dfsg.1-14sarge4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xlibs-dbg", ver:"4.3.0.dfsg.1-14sarge4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xlibs-dev", ver:"4.3.0.dfsg.1-14sarge4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xlibs-pic", ver:"4.3.0.dfsg.1-14sarge4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xlibs-static-dev", ver:"4.3.0.dfsg.1-14sarge4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xlibs-static-pic", ver:"4.3.0.dfsg.1-14sarge4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xlibs", ver:"4.3.0.dfsg.1-14sarge4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xmh", ver:"4.3.0.dfsg.1-14sarge4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xnest", ver:"4.3.0.dfsg.1-14sarge4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xserver-common", ver:"4.3.0.dfsg.1-14sarge4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xserver-xfree86-dbg", ver:"4.3.0.dfsg.1-14sarge4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xserver-xfree86", ver:"4.3.0.dfsg.1-14sarge4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xspecs", ver:"4.3.0.dfsg.1-14sarge4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xterm", ver:"4.3.0.dfsg.1-14sarge4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xutils", ver:"4.3.0.dfsg.1-14sarge4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xvfb", ver:"4.3.0.dfsg.1-14sarge4", rls:"DEB3.1"))) {
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
