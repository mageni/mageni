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
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2014.96");
  script_cve_id("CVE-2014-2490", "CVE-2014-4209", "CVE-2014-4216", "CVE-2014-4218", "CVE-2014-4219", "CVE-2014-4244", "CVE-2014-4252", "CVE-2014-4262", "CVE-2014-4263", "CVE-2014-4266", "CVE-2014-4268", "CVE-2014-6457", "CVE-2014-6502", "CVE-2014-6504", "CVE-2014-6506", "CVE-2014-6511", "CVE-2014-6512", "CVE-2014-6517", "CVE-2014-6519", "CVE-2014-6531", "CVE-2014-6558");
  script_tag(name:"creation_date", value:"2023-03-08 12:56:44 +0000 (Wed, 08 Mar 2023)");
  script_version("2023-03-09T10:09:19+0000");
  script_tag(name:"last_modification", value:"2023-03-09 10:09:19 +0000 (Thu, 09 Mar 2023)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DLA-96)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB6");

  script_xref(name:"Advisory-ID", value:"DLA-96");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2014/dla-96");
  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts/");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'openjdk-6' package(s) announced via the DLA-96 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in OpenJDK, an implementation of the Oracle Java platform, resulting in the execution of arbitrary code, breakouts of the Java sandbox, information disclosure or denial of service.

For Debian 6 Squeeze, these problems have been fixed in version 6b33-1.13.5-2~deb6u1.

We recommend that you upgrade your openjdk-6 packages and that you subscribe to [link moved to references] to help test updated packages before we release them.");

  script_tag(name:"affected", value:"'openjdk-6' package(s) on Debian 6.");

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

  if(!isnull(res = isdpkgvuln(pkg:"icedtea-6-jre-cacao", ver:"6b33-1.13.5-2~deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-6-dbg", ver:"6b33-1.13.5-2~deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-6-demo", ver:"6b33-1.13.5-2~deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-6-doc", ver:"6b33-1.13.5-2~deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-6-jdk", ver:"6b33-1.13.5-2~deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-6-jre-headless", ver:"6b33-1.13.5-2~deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-6-jre-lib", ver:"6b33-1.13.5-2~deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-6-jre-zero", ver:"6b33-1.13.5-2~deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-6-jre", ver:"6b33-1.13.5-2~deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-6-source", ver:"6b33-1.13.5-2~deb6u1", rls:"DEB6"))) {
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
