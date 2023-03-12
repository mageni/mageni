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
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2015.140");
  script_cve_id("CVE-2012-0060", "CVE-2012-0061", "CVE-2012-0815", "CVE-2013-6435", "CVE-2014-8118");
  script_tag(name:"creation_date", value:"2023-03-08 12:56:44 +0000 (Wed, 08 Mar 2023)");
  script_version("2023-03-09T10:09:19+0000");
  script_tag(name:"last_modification", value:"2023-03-09 10:09:19 +0000 (Thu, 09 Mar 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DLA-140)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB6");

  script_xref(name:"Advisory-ID", value:"DLA-140");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2015/dla-140");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'rpm' package(s) announced via the DLA-140 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been fixed in rpm:

CVE-2014-8118

Fix integer overflow which allowed remote attackers to execute arbitrary code.

CVE-2013-6435

Prevent remote attackers from executing arbitrary code via crafted RPM files.

CVE-2012-0815

Fix denial of service and possible code execution via negative value in region offset in crafted RPM files.

CVE-2012-0060

and CVE-2012-0061

Prevent denial of service (crash) and possibly execute arbitrary code execution via an invalid region tag in RPM files.

We recommend that you upgrade your rpm packages.

For Debian 6 Squeeze, these issues have been fixed in rpm version 4.8.1-6+squeeze2");

  script_tag(name:"affected", value:"'rpm' package(s) on Debian 6.");

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

  if(!isnull(res = isdpkgvuln(pkg:"librpm-dbg", ver:"4.8.1-6+squeeze2", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"librpm-dev", ver:"4.8.1-6+squeeze2", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"librpm1", ver:"4.8.1-6+squeeze2", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"librpmbuild1", ver:"4.8.1-6+squeeze2", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"librpmio1", ver:"4.8.1-6+squeeze2", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lsb-rpm", ver:"4.8.1-6+squeeze2", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python-rpm", ver:"4.8.1-6+squeeze2", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rpm-common", ver:"4.8.1-6+squeeze2", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rpm-i18n", ver:"4.8.1-6+squeeze2", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rpm2cpio", ver:"4.8.1-6+squeeze2", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rpm", ver:"4.8.1-6+squeeze2", rls:"DEB6"))) {
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
