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
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2015.263");
  script_cve_id("CVE-2012-5371", "CVE-2013-0269");
  script_tag(name:"creation_date", value:"2023-03-08 12:56:44 +0000 (Wed, 08 Mar 2023)");
  script_version("2023-03-09T10:09:19+0000");
  script_tag(name:"last_modification", value:"2023-03-09 10:09:19 +0000 (Thu, 09 Mar 2023)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DLA-263)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB6");

  script_xref(name:"Advisory-ID", value:"DLA-263");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2015/dla-263");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'ruby1.9.1' package(s) announced via the DLA-263 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Two vulnerabilities were identified in the Ruby language interpreter, version 1.9.1.

CVE-2012-5371

Jean-Philippe Aumasson identified that Ruby computed hash values without properly restricting the ability to trigger hash collisions predictably, allowing context-dependent attackers to cause a denial of service (CPU consumption). This is a different vulnerability than CVE-2011-4815.

CVE-2013-0269

Thomas Hollstegge and Ben Murphy found that the JSON gem for Ruby allowed remote attackers to cause a denial of service (resource consumption) or bypass the mass assignment protection mechanism via a crafted JSON document that triggers the creation of arbitrary Ruby symbols or certain internal objects.

For the squeeze distribution, theses vulnerabilities have been fixed in version 1.9.2.0-2+deb6u5 of ruby1.9.1. We recommend that you upgrade your ruby1.9.1 package.");

  script_tag(name:"affected", value:"'ruby1.9.1' package(s) on Debian 6.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libruby1.9.1-dbg", ver:"1.9.2.0-2+deb6u5", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libruby1.9.1", ver:"1.9.2.0-2+deb6u5", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libtcltk-ruby1.9.1", ver:"1.9.2.0-2+deb6u5", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ri1.9.1", ver:"1.9.2.0-2+deb6u5", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ruby1.9.1-dev", ver:"1.9.2.0-2+deb6u5", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ruby1.9.1-elisp", ver:"1.9.2.0-2+deb6u5", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ruby1.9.1-examples", ver:"1.9.2.0-2+deb6u5", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ruby1.9.1-full", ver:"1.9.2.0-2+deb6u5", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ruby1.9.1", ver:"1.9.2.0-2+deb6u5", rls:"DEB6"))) {
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
