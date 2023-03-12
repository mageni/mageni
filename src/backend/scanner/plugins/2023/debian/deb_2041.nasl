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
  script_oid("1.3.6.1.4.1.25623.1.1.1.1.2010.2041");
  script_cve_id("CVE-2010-1150");
  script_tag(name:"creation_date", value:"2023-03-08 12:56:44 +0000 (Wed, 08 Mar 2023)");
  script_version("2023-03-09T10:09:19+0000");
  script_tag(name:"last_modification", value:"2023-03-09 10:09:19 +0000 (Thu, 09 Mar 2023)");
  script_tag(name:"cvss_base", value:"6.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-2041)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB5");

  script_xref(name:"Advisory-ID", value:"DSA-2041");
  script_xref(name:"URL", value:"https://www.debian.org/security/2010/dsa-2041");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'mediawiki' package(s) announced via the DSA-2041 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that mediawiki, a website engine for collaborative work, is vulnerable to a Cross-Site Request Forgery login attack, which could be used to conduct phishing or similar attacks to users via affected mediawiki installations.

Note that the fix used breaks the login API and may require clients using it to be updated.

For the stable distribution (lenny), this problem has been fixed in version 1:1.12.0-2lenny5.

For the testing distribution (squeeze) and the unstable distribution (sid), this problem has been fixed in version 1:1.15.3-1.

We recommend that you upgrade your mediawiki packages.");

  script_tag(name:"affected", value:"'mediawiki' package(s) on Debian 5.");

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

  if(!isnull(res = isdpkgvuln(pkg:"mediawiki-math", ver:"1:1.12.0-2lenny5", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mediawiki", ver:"1:1.12.0-2lenny5", rls:"DEB5"))) {
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
