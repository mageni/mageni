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
  script_oid("1.3.6.1.4.1.25623.1.1.1.1.2010.2014");
  script_cve_id("CVE-2010-0668", "CVE-2010-0669", "CVE-2010-0717");
  script_tag(name:"creation_date", value:"2023-03-08 12:56:44 +0000 (Wed, 08 Mar 2023)");
  script_version("2023-03-09T10:09:19+0000");
  script_tag(name:"last_modification", value:"2023-03-09 10:09:19 +0000 (Thu, 09 Mar 2023)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-2014)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB5");

  script_xref(name:"Advisory-ID", value:"DSA-2014");
  script_xref(name:"URL", value:"https://www.debian.org/security/2010/dsa-2014");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'moin' package(s) announced via the DSA-2014 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in moin, a python clone of WikiWiki. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2010-0668

Multiple security issues in MoinMoin related to configurations that have a non-empty superuser list, the xmlrpc action enabled, the SyncPages action enabled, or OpenID configured.

CVE-2010-0669

MoinMoin does not properly sanitize user profiles.

CVE-2010-0717

The default configuration of cfg.packagepages_actions_excluded in MoinMoin does not prevent unsafe package actions.

In addition, this update fixes an error when processing hierarchical ACLs, which can be exploited to access restricted sub-pages.

For the stable distribution (lenny), these problems have been fixed in version 1.7.1-3+lenny3.

For the unstable distribution (sid), these problems have been fixed in version 1.9.2-1, and will migrate to the testing distribution (squeeze) shortly.

We recommend that you upgrade your moin package.");

  script_tag(name:"affected", value:"'moin' package(s) on Debian 5.");

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

  if(!isnull(res = isdpkgvuln(pkg:"python-moinmoin", ver:"1.7.1-3+lenny3", rls:"DEB5"))) {
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
