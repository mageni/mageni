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
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2015.316");
  script_cve_id("CVE-2014-8121", "CVE-2015-8777", "CVE-2015-8983", "CVE-2015-8984");
  script_tag(name:"creation_date", value:"2023-03-08 12:56:44 +0000 (Wed, 08 Mar 2023)");
  script_version("2023-03-09T10:09:19+0000");
  script_tag(name:"last_modification", value:"2023-03-09 10:09:19 +0000 (Thu, 09 Mar 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-03-22 19:12:00 +0000 (Wed, 22 Mar 2017)");

  script_name("Debian: Security Advisory (DLA-316)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB6");

  script_xref(name:"Advisory-ID", value:"DLA-316");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2015/dla-316");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'eglibc' package(s) announced via the DLA-316 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in eglibc that may lead to a privilege escalation or denial of service.

Glibc pointer guarding weakness A weakness in the dynamic loader prior has been found. The issue is that the LD_POINTER_GUARD in the environment is not sanitized allowing local attackers easily to bypass the pointer guarding protection on set-user-ID and set-group-ID programs.

Potential application crash due to overread in fnmatch When processing certain malformed patterns, fnmatch can skip over the NUL byte terminating the pattern. This can potentially result in an application crash if fnmatch hits an unmapped page before encountering a NUL byte.

_IO_wstr_overflow integer overflow A miscalculation in _IO_wstr_overflow could potentially be exploited to overflow a buffer.

CVE-2014-8121

DB_LOOKUP in nss_files/files-XXX.c in the Name Service Switch (NSS) in GNU C Library (aka glibc or libc6) 2.21 and earlier does not properly check if a file is open, which allows remote attackers to cause a denial of service (infinite loop) by performing a look-up while the database is iterated over the database, which triggers the file pointer to be reset.

For the oldoldstable distribution (squeeze), these problems have been fixed in version 2.11.3-4+deb6u7.

We recommend that you update your packages.");

  script_tag(name:"affected", value:"'eglibc' package(s) on Debian 6.");

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

if(release == "DEB6") {

  if(!isnull(res = isdpkgvuln(pkg:"eglibc-source", ver:"2.11.3-4+deb6u7", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"glibc-doc", ver:"2.11.3-4+deb6u7", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libc-bin", ver:"2.11.3-4+deb6u7", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libc-dev-bin", ver:"2.11.3-4+deb6u7", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libc6-amd64", ver:"2.11.3-4+deb6u7", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libc6-dbg", ver:"2.11.3-4+deb6u7", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libc6-dev-amd64", ver:"2.11.3-4+deb6u7", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libc6-dev-i386", ver:"2.11.3-4+deb6u7", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libc6-dev", ver:"2.11.3-4+deb6u7", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libc6-i386", ver:"2.11.3-4+deb6u7", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libc6-i686", ver:"2.11.3-4+deb6u7", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libc6-pic", ver:"2.11.3-4+deb6u7", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libc6-prof", ver:"2.11.3-4+deb6u7", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libc6-udeb", ver:"2.11.3-4+deb6u7", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libc6-xen", ver:"2.11.3-4+deb6u7", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libc6", ver:"2.11.3-4+deb6u7", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libnss-dns-udeb", ver:"2.11.3-4+deb6u7", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libnss-files-udeb", ver:"2.11.3-4+deb6u7", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"locales-all", ver:"2.11.3-4+deb6u7", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"locales", ver:"2.11.3-4+deb6u7", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nscd", ver:"2.11.3-4+deb6u7", rls:"DEB6"))) {
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
