# Copyright (C) 2019 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) the respective author(s)
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
  script_oid("1.3.6.1.4.1.25623.1.0.891934");
  script_version("2019-09-29T02:00:25+0000");
  script_cve_id("CVE-2018-7588", "CVE-2018-7589", "CVE-2018-7637", "CVE-2018-7638", "CVE-2018-7639", "CVE-2018-7640", "CVE-2018-7641", "CVE-2019-1010174");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2019-09-29 02:00:25 +0000 (Sun, 29 Sep 2019)");
  script_tag(name:"creation_date", value:"2019-09-29 02:00:25 +0000 (Sun, 29 Sep 2019)");
  script_name("Debian LTS Advisory ([SECURITY] [DLA 1934-1] cimg security update)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2019/09/msg00030.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-1934-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'cimg'
  package(s) announced via the DSA-1934-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several issues have been found in cimg, a powerful image processing
library.

CVE-2019-1010174 is related to a missing string sanitization on URLs,
which might result in a command injection when loading a special crafted
image.

The other CVEs are about heap-based buffer over-reads or double frees when
loading an image.");

  script_tag(name:"affected", value:"'cimg' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 8 'Jessie', these problems have been fixed in version
1.5.9+dfsg-1+deb8u1.

We recommend that you upgrade your cimg packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"cimg-dev", ver:"1.5.9+dfsg-1+deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"cimg-doc", ver:"1.5.9+dfsg-1+deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"cimg-examples", ver:"1.5.9+dfsg-1+deb8u1", rls:"DEB8"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);