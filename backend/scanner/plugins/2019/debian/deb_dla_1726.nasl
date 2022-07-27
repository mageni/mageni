# Copyright (C) 2019 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) the respective author(s)
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
  script_oid("1.3.6.1.4.1.25623.1.0.891726");
  script_version("2019-04-04T06:31:10+0000");
  script_cve_id("CVE-2016-9401", "CVE-2019-9924");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-04-04 06:31:10 +0000 (Thu, 04 Apr 2019)");
  script_tag(name:"creation_date", value:"2019-03-25 23:00:00 +0100 (Mon, 25 Mar 2019)");
  script_name("Debian LTS Advisory ([SECURITY] [DLA 1726-1] bash security update)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2019/03/msg00028.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-1726-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'bash'
  package(s) announced via the DSA-1726-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Two issues have been fixed in bash, the GNU Bourne-Again Shell:

CVE-2016-9401

The popd builtin segfaulted when called with negative out of range
offsets.

CVE-2019-9924

Sylvain Beucler discovered that it was possible to call commands
that contained a slash when in restricted mode (rbash) by adding
them to the BASH_CMDS array.");

  script_tag(name:"affected", value:"'bash' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 8 'Jessie', these problems have been fixed in version
4.3-11+deb8u2.

We recommend that you upgrade your bash packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"bash", ver:"4.3-11+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"bash-builtins", ver:"4.3-11+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"bash-doc", ver:"4.3-11+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"bash-static", ver:"4.3-11+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);