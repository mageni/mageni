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
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2014.58");
  script_cve_id("CVE-2014-6273");
  script_tag(name:"creation_date", value:"2023-03-08 12:56:44 +0000 (Wed, 08 Mar 2023)");
  script_version("2023-03-09T10:09:19+0000");
  script_tag(name:"last_modification", value:"2023-03-09 10:09:19 +0000 (Thu, 09 Mar 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DLA-58)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB6");

  script_xref(name:"Advisory-ID", value:"DLA-58");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2014/dla-58-3");
  script_xref(name:"URL", value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bugq0924");
  script_xref(name:"URL", value:"http://anonscm.debian.org/cgit/apt/apt.git/commit/?id31e8396ee5a4f2e7d276eddc54749b2a13dd789");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'apt' package(s) announced via the DLA-58 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The recent security updates to apt make apt bug #710924 [1] much easier to trigger. Affected users see 416 Requested Range Not Satisfiable errors during a apt-get update operation. With the 0.8.10.3+squeeze7 upload the fix for this error that was originally introduced in version 0.9.12 [2] is now backported.

[1] [link moved to references] [2] [link moved to references]

For Debian 6 Squeeze, these issues have been fixed in apt version 0.8.10.3+squeeze7");

  script_tag(name:"affected", value:"'apt' package(s) on Debian 6.");

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

  if(!isnull(res = isdpkgvuln(pkg:"apt-doc", ver:"0.8.10.3+squeeze5", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"apt-transport-https", ver:"0.8.10.3+squeeze5", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"apt-utils", ver:"0.8.10.3+squeeze5", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"apt", ver:"0.8.10.3+squeeze5", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libapt-pkg-dev", ver:"0.8.10.3+squeeze5", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libapt-pkg-doc", ver:"0.8.10.3+squeeze5", rls:"DEB6"))) {
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
