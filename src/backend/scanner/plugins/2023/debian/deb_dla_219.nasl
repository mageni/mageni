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
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2015.219");
  script_cve_id("CVE-2013-1569", "CVE-2013-2383", "CVE-2013-2384", "CVE-2013-2419", "CVE-2014-6585", "CVE-2014-6591", "CVE-2014-7923", "CVE-2014-7926", "CVE-2014-7940", "CVE-2014-9654");
  script_tag(name:"creation_date", value:"2023-03-08 12:56:44 +0000 (Wed, 08 Mar 2023)");
  script_version("2023-03-09T10:09:19+0000");
  script_tag(name:"last_modification", value:"2023-03-09 10:09:19 +0000 (Thu, 09 Mar 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-04-23 19:29:00 +0000 (Tue, 23 Apr 2019)");

  script_name("Debian: Security Advisory (DLA-219)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB6");

  script_xref(name:"Advisory-ID", value:"DLA-219");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2015/dla-219");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'icu' package(s) announced via the DLA-219 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities were discovered in the International Components for Unicode (ICU) library:

CVE-2013-1569

Glyph table issue.

CVE-2013-2383

Glyph table issue.

CVE-2013-2384

Font layout issue.

CVE-2013-2419

Font processing issue.

CVE-2014-6585

Out-of-bounds read.

CVE-2014-6591

Additional out-of-bounds reads.

CVE-2014-7923

Memory corruption in regular expression comparison.

CVE-2014-7926

Memory corruption in regular expression comparison.

CVE-2014-7940

Uninitialized memory.

CVE-2014-9654

More regular expression flaws.

For Debian 6 Squeeze, these issues have been fixed in icu version 4.4.1-8+squeeze3.");

  script_tag(name:"affected", value:"'icu' package(s) on Debian 6.");

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

  if(!isnull(res = isdpkgvuln(pkg:"icu-doc", ver:"4.4.1-8+squeeze3", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lib32icu-dev", ver:"4.4.1-8+squeeze3", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lib32icu44", ver:"4.4.1-8+squeeze3", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libicu-dev", ver:"4.4.1-8+squeeze3", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libicu44-dbg", ver:"4.4.1-8+squeeze3", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libicu44", ver:"4.4.1-8+squeeze3", rls:"DEB6"))) {
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
