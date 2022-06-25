# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.892293");
  script_version("2020-08-01T03:00:12+0000");
  script_cve_id("CVE-2017-17458", "CVE-2018-1000132", "CVE-2018-13346", "CVE-2018-13347", "CVE-2018-13348", "CVE-2019-3902");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2020-08-03 11:16:30 +0000 (Mon, 03 Aug 2020)");
  script_tag(name:"creation_date", value:"2020-08-01 03:00:12 +0000 (Sat, 01 Aug 2020)");
  script_name("Debian LTS: Security Advisory for mercurial (DLA-2293-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2020/07/msg00032.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-2293-1");
  script_xref(name:"URL", value:"https://bugs.debian.org/901050");
  script_xref(name:"URL", value:"https://bugs.debian.org/892964");
  script_xref(name:"URL", value:"https://bugs.debian.org/927674");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mercurial'
  package(s) announced via the DLA-2293-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities were discovered in mercurial, an easy-to-use,
scalable distributed version control system.

CVE-2017-17458

In Mercurial before 4.4.1, it is possible that a specially
malformed repository can cause Git subrepositories to run
arbitrary code in the form of a .git/hooks/post-update script
checked into the repository. Typical use of Mercurial prevents
construction of such repositories, but they can be created
programmatically.

CVE-2018-13346

The mpatch_apply function in mpatch.c in Mercurial before 4.6.1
incorrectly proceeds in cases where the fragment start is past the
end of the original data.

CVE-2018-13347

mpatch.c in Mercurial before 4.6.1 mishandles integer addition and
subtraction.

CVE-2018-13348

The mpatch_decode function in mpatch.c in Mercurial before 4.6.1
mishandles certain situations where there should be at least 12
bytes remaining after the current position in the patch data, but
actually are not.

CVE-2018-1000132

Mercurial version 4.5 and earlier contains a Incorrect Access
Control (CWE-285) vulnerability in Protocol server that can result
in Unauthorized data access. This attack appear to be exploitable
via network connectivity. This vulnerability appears to have been
fixed in 4.5.1.

CVE-2019-3902

Symbolic links and subrepositories could be used defeat Mercurial's
path-checking logic and write files outside the repository root.");

  script_tag(name:"affected", value:"'mercurial' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 9 stretch, these problems have been fixed in version
4.0-1+deb9u2.

We recommend that you upgrade your mercurial packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"mercurial", ver:"4.0-1+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"mercurial-common", ver:"4.0-1+deb9u2", rls:"DEB9"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
