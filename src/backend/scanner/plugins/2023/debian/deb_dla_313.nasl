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
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2015.313");
  script_cve_id("CVE-2013-3792", "CVE-2014-2486", "CVE-2014-2488", "CVE-2014-2489", "CVE-2015-2594");
  script_tag(name:"creation_date", value:"2023-03-08 12:56:44 +0000 (Wed, 08 Mar 2023)");
  script_version("2023-03-09T10:09:19+0000");
  script_tag(name:"last_modification", value:"2023-03-09 10:09:19 +0000 (Thu, 09 Mar 2023)");
  script_tag(name:"cvss_base", value:"6.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:S/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DLA-313)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB6");

  script_xref(name:"Advisory-ID", value:"DLA-313");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2015/dla-313");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'virtualbox-ose' package(s) announced via the DLA-313 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The latest maintenance release of the VirtualBox (OSE) 3.2.x series (i.e., version 3.2.28) has been uploaded to Debian LTS (squeeze). Thanks to Gianfranco Costamagna for preparing packages for review and upload by the Debian LTS Team.

Unfortunately, Oracle no longer provides information on specific security vulnerabilities in VirtualBox, thus we provide their latest 3.2.28 maintenance release in Debian LTS (squeeze) directly.

CVE-2013-3792

Oracle reported an unspecified vulnerability in the Oracle VM VirtualBox component in Oracle Virtualization VirtualBox prior to 3.2.18, 4.0.20, 4.1.28, and 4.2.18 allows local users to affect availability via unknown vectors related to Core.

The fix for CVE-2013-3792 prevents a virtio-net host DoS vulnerability by adding large frame support to IntNet, VirtioNet and NetFilter plus dropping oversized frames.

CVE-2014-2486

Unspecified vulnerability in the Oracle VM VirtualBox component in Oracle Virtualization VirtualBox before 3.2.24, 4.0.26, 4.1.34, 4.2.26, and 4.3.12 allows local users to affect integrity and availability via unknown vectors related to Core.

No further details have been provided, the attack range has been given as local, severity low.

CVE-2014-2488

Unspecified vulnerability in the Oracle VM VirtualBox component in Oracle Virtualization VirtualBox before 3.2.24, 4.0.26, 4.1.34, 4.2.26, and 4.3.12 allows local users to affect confidentiality via unknown vectors related to Core.

No further details can been provided, the attack range has been given as local, severity low.

CVE-2014-2489

Unspecified vulnerability in the Oracle VM VirtualBox component in Oracle Virtualization VirtualBox before 3.2.24, 4.0.26, 4.1.34, 4.2.26, and 4.3.12 allows local users to affect confidentiality, integrity, and availability via unknown vectors related to Core.

No further details can been provided, the attack range has been given as local, severity medium.

CVE-2015-2594

Unspecified vulnerability in the Oracle VM VirtualBox component in Oracle Virtualization VirtualBox prior to 4.0.32, 4.1.40, 4.2.32, and 4.3.30 allows local users to affect confidentiality, integrity, and availability via unknown vectors related to Core.

This update fixes an issue related to guests using bridged networking via WiFi.");

  script_tag(name:"affected", value:"'virtualbox-ose' package(s) on Debian 6.");

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

  if(!isnull(res = isdpkgvuln(pkg:"virtualbox-ose-dbg", ver:"3.2.28-dfsg-1+squeeze1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"virtualbox-ose-dkms", ver:"3.2.28-dfsg-1+squeeze1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"virtualbox-ose-fuse", ver:"3.2.28-dfsg-1+squeeze1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"virtualbox-ose-guest-dkms", ver:"3.2.28-dfsg-1+squeeze1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"virtualbox-ose-guest-source", ver:"3.2.28-dfsg-1+squeeze1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"virtualbox-ose-guest-utils", ver:"3.2.28-dfsg-1+squeeze1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"virtualbox-ose-guest-x11", ver:"3.2.28-dfsg-1+squeeze1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"virtualbox-ose-qt", ver:"3.2.28-dfsg-1+squeeze1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"virtualbox-ose-source", ver:"3.2.28-dfsg-1+squeeze1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"virtualbox-ose", ver:"3.2.28-dfsg-1+squeeze1", rls:"DEB6"))) {
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
