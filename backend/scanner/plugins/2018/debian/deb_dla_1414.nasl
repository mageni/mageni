###############################################################################
# OpenVAS Vulnerability Test
# $Id: deb_dla_1414.nasl 14281 2019-03-18 14:53:48Z cfischer $
#
# Auto-generated from advisory DLA 1414-1 using nvtgen 1.0
# Script version: 1.0
#
# Author:
# Greenbone Networks
#
# Copyright:
# Copyright (c) 2018 Greenbone Networks GmbH http://greenbone.net
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (c) the respective author(s)
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.891414");
  script_version("$Revision: 14281 $");
  script_cve_id("CVE-2017-17458", "CVE-2017-9462", "CVE-2018-1000132");
  script_name("Debian LTS Advisory ([SECURITY] [DLA 1414-1] mercurial security update)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:53:48 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2018-07-10 00:00:00 +0200 (Tue, 10 Jul 2018)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2018/07/msg00005.html");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (c) 2018 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");
  script_tag(name:"affected", value:"mercurial on Debian Linux");
  script_tag(name:"solution", value:"For Debian 8 'Jessie', these problems have been fixed in version
3.1.2-2+deb8u5.

We recommend that you upgrade your mercurial packages.");
  script_tag(name:"summary", value:"Some security vulnerabilities were found in Mercurial which allow
authenticated users to trigger arbitrary code execution and
unauthorized data access in certain server configuration. Malformed
patches and repositories can also lead to crashes and arbitrary code
execution on clients.

CVE-2017-9462

In Mercurial before 4.1.3, 'hg serve --stdio' allows remote
authenticated users to launch the Python debugger, and
consequently execute arbitrary code, by using --debugger as a
repository name.

CVE-2017-17458

In Mercurial before 4.4.1, it is possible that a specially
malformed repository can cause Git subrepositories to run
arbitrary code in the form of a .git/hooks/post-update script
checked into the repository. Typical use of Mercurial prevents
construction of such repositories, but they can be created
programmatically.

CVE-2018-1000132

Mercurial version 4.5 and earlier contains a Incorrect Access
Control (CWE-285) vulnerability in Protocol server that can result
in Unauthorized data access. This attack appear to be exploitable
via network connectivity. This vulnerability appears to have been
fixed in 4.5.1.

OVE-20180430-0001

mpatch: be more careful about parsing binary patch data

OVE-20180430-0002

mpatch: protect against underflow in mpatch_apply

OVE-20180430-0004

mpatch: ensure fragment start isn't past the end of orig");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"mercurial", ver:"3.1.2-2+deb8u5", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"mercurial-common", ver:"3.1.2-2+deb8u5", rls:"DEB8")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}