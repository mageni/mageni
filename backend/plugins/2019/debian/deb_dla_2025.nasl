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
  script_oid("1.3.6.1.4.1.25623.1.0.892025");
  script_version("2019-12-09T03:00:12+0000");
  script_cve_id("CVE-2017-17833", "CVE-2019-5544");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2019-12-09 03:00:12 +0000 (Mon, 09 Dec 2019)");
  script_tag(name:"creation_date", value:"2019-12-09 03:00:12 +0000 (Mon, 09 Dec 2019)");
  script_name("Debian LTS Advisory ([SECURITY] [DLA 2025-1] openslp-dfsg security update)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2019/12/msg00007.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-2025-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openslp-dfsg'
  package(s) announced via the DSA-2025-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The OpenSLP package had two open security issues:

CVE-2017-17833

OpenSLP releases in the 1.0.2 and 1.1.0 code streams have a heap-related
memory corruption issue which may manifest itself as a denial-of-service
or a remote code-execution vulnerability.

CVE-2019-5544

OpenSLP as used in ESXi and the Horizon DaaS appliances has a heap
overwrite issue. VMware has evaluated the severity of this issue to be in
the critical severity range.");

  script_tag(name:"affected", value:"'openslp-dfsg' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 8 'Jessie', these problems have been fixed in version
1.2.1-10+deb8u2.

We recommend that you upgrade your openslp-dfsg packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"libslp-dev", ver:"1.2.1-10+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libslp1", ver:"1.2.1-10+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"openslp-doc", ver:"1.2.1-10+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"slpd", ver:"1.2.1-10+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"slptool", ver:"1.2.1-10+deb8u2", rls:"DEB8"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
