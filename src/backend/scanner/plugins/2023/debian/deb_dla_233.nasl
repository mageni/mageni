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
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2015.233");
  script_cve_id("CVE-2014-9328", "CVE-2015-1461", "CVE-2015-1462", "CVE-2015-1463", "CVE-2015-2170", "CVE-2015-2221", "CVE-2015-2222", "CVE-2015-2305", "CVE-2015-2668");
  script_tag(name:"creation_date", value:"2023-03-08 12:56:44 +0000 (Wed, 08 Mar 2023)");
  script_version("2023-03-09T10:09:19+0000");
  script_tag(name:"last_modification", value:"2023-03-09 10:09:19 +0000 (Thu, 09 Mar 2023)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DLA-233)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB6");

  script_xref(name:"Advisory-ID", value:"DLA-233");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2015/dla-233");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'clamav' package(s) announced via the DLA-233 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Upstream published version 0.98.7. This update updates sqeeze-lts to the latest upstream release in line with the approach used for other Debian releases.

The changes are not strictly required for operation, but users of the previous version in Squeeze may not be able to make use of all current virus signatures and might get warnings.

The bug fixes that are part of this release include security fixes related to packed or crypted files (CVE-2014-9328, CVE-2015-1461, CVE-2015-1462, CVE-2015-1463, CVE-2015-2170, CVE-2015-2221, CVE-2015-2222, and CVE-2015-2668) and several fixes to the embedded libmspack library, including a potential infinite loop in the Quantum decoder (CVE-2014-9556).

If you use clamav, we strongly recommend that you upgrade to this version.");

  script_tag(name:"affected", value:"'clamav' package(s) on Debian 6.");

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

  if(!isnull(res = isdpkgvuln(pkg:"clamav-base", ver:"0.98.7+dfsg-0+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"clamav-daemon", ver:"0.98.7+dfsg-0+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"clamav-dbg", ver:"0.98.7+dfsg-0+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"clamav-docs", ver:"0.98.7+dfsg-0+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"clamav-freshclam", ver:"0.98.7+dfsg-0+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"clamav-milter", ver:"0.98.7+dfsg-0+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"clamav-testfiles", ver:"0.98.7+dfsg-0+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"clamav", ver:"0.98.7+dfsg-0+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libclamav-dev", ver:"0.98.7+dfsg-0+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libclamav6", ver:"0.98.7+dfsg-0+deb6u1", rls:"DEB6"))) {
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
