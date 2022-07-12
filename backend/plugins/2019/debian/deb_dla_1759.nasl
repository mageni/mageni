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
  script_oid("1.3.6.1.4.1.25623.1.0.891759");
  script_version("2019-04-23T02:00:07+0000");
  script_cve_id("CVE-2019-1787", "CVE-2019-1788", "CVE-2019-1789");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2019-04-23 02:00:07 +0000 (Tue, 23 Apr 2019)");
  script_tag(name:"creation_date", value:"2019-04-23 02:00:07 +0000 (Tue, 23 Apr 2019)");
  script_name("Debian LTS Advisory ([SECURITY] [DLA 1759-1] clamav security update)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2019/04/msg00019.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-1759-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'clamav'
  package(s) announced via the DSA-1759-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Out-of-bounds read and write conditions have been fixed in clamav.

CVE-2019-1787

An out-of-bounds heap read condition may occur when scanning PDF
documents. The defect is a failure to correctly keep track of the number
of bytes remaining in a buffer when indexing file data.

CVE-2019-1788

An out-of-bounds heap write condition may occur when scanning OLE2 files
such as Microsoft Office 97-2003 documents. The invalid write happens when
an invalid pointer is mistakenly used to initialize a 32bit integer to
zero. This is likely to crash the application.

CVE-2019-1789

An out-of-bounds heap read condition may occur when scanning PE files
(i.e. Windows EXE and DLL files) that have been packed using Aspack as a
result of inadequate bound-checking.");

  script_tag(name:"affected", value:"'clamav' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 8 'Jessie', these problems have been fixed in version
0.100.3+dfsg-0+deb8u1.

We recommend that you upgrade your clamav packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"clamav", ver:"0.100.3+dfsg-0+deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"clamav-base", ver:"0.100.3+dfsg-0+deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"clamav-daemon", ver:"0.100.3+dfsg-0+deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"clamav-dbg", ver:"0.100.3+dfsg-0+deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"clamav-docs", ver:"0.100.3+dfsg-0+deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"clamav-freshclam", ver:"0.100.3+dfsg-0+deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"clamav-milter", ver:"0.100.3+dfsg-0+deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"clamav-testfiles", ver:"0.100.3+dfsg-0+deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"clamdscan", ver:"0.100.3+dfsg-0+deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libclamav-dev", ver:"0.100.3+dfsg-0+deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libclamav7", ver:"0.100.3+dfsg-0+deb8u1", rls:"DEB8"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);