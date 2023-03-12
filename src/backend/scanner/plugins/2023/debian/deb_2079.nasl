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
  script_oid("1.3.6.1.4.1.25623.1.1.1.1.2010.2079");
  script_cve_id("CVE-2010-2539", "CVE-2010-2540");
  script_tag(name:"creation_date", value:"2023-03-08 12:56:44 +0000 (Wed, 08 Mar 2023)");
  script_version("2023-03-09T10:09:19+0000");
  script_tag(name:"last_modification", value:"2023-03-09 10:09:19 +0000 (Thu, 09 Mar 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-2079)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB5");

  script_xref(name:"Advisory-ID", value:"DSA-2079");
  script_xref(name:"URL", value:"https://www.debian.org/security/2010/dsa-2079");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'mapserver' package(s) announced via the DSA-2079 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in mapserver, a CGI-based web framework to publish spatial data and interactive mapping applications. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2010-2539

A stack-based buffer overflow in the msTmpFile function might lead to arbitrary code execution under some conditions.

CVE-2010-2540

It was discovered that the CGI debug command-line arguments which are enabled by default are insecure and may allow a remote attacker to execute arbitrary code. Therefore they have been disabled by default.

For the stable distribution (lenny), this problem has been fixed in version 5.0.3-3+lenny5.

For the testing distribution (squeeze), this problem has been fixed in version 5.6.4-1.

For the unstable distribution (sid), this problem has been fixed in version 5.6.4-1.

We recommend that you upgrade your mapserver packages.");

  script_tag(name:"affected", value:"'mapserver' package(s) on Debian 5.");

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

if(release == "DEB5") {

  if(!isnull(res = isdpkgvuln(pkg:"cgi-mapserver", ver:"5.0.3-3+lenny5", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmapscript-ruby1.8", ver:"5.0.3-3+lenny5", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmapscript-ruby1.9", ver:"5.0.3-3+lenny5", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmapscript-ruby", ver:"5.0.3-3+lenny5", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mapserver-bin", ver:"5.0.3-3+lenny5", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mapserver-doc", ver:"5.0.3-3+lenny5", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"perl-mapscript", ver:"5.0.3-3+lenny5", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php5-mapscript", ver:"5.0.3-3+lenny5", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python-mapscript", ver:"5.0.3-3+lenny5", rls:"DEB5"))) {
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
