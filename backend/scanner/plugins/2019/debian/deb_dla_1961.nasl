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
  script_oid("1.3.6.1.4.1.25623.1.0.891961");
  script_version("2019-10-22T02:00:41+0000");
  script_cve_id("CVE-2019-14464", "CVE-2019-14496", "CVE-2019-14497");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2019-10-22 02:00:41 +0000 (Tue, 22 Oct 2019)");
  script_tag(name:"creation_date", value:"2019-10-22 02:00:41 +0000 (Tue, 22 Oct 2019)");
  script_name("Debian LTS Advisory ([SECURITY] [DLA 1961-1] milkytracker security update)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2019/10/msg00029.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-1961-1");
  script_xref(name:"URL", value:"https://bugs.debian.org/933964");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'milkytracker'
  package(s) announced via the DSA-1961-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Fredric discovered a couple of buffer overflows in MilkyTracker, of which,
a brief description is given below.

CVE-2019-14464

XMFile::read in XMFile.cpp in milkyplay in MilkyTracker had a heap-based
buffer overflow.

CVE-2019-14496

LoaderXM::load in LoaderXM.cpp in milkyplay in MilkyTracker had a
stack-based buffer overflow.

CVE-2019-14497

ModuleEditor::convertInstrument in tracker/ModuleEditor.cpp in MilkyTracker
had a heap-based buffer overflow.");

  script_tag(name:"affected", value:"'milkytracker' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 8 'Jessie', these problems have been fixed in version
0.90.85+dfsg-2.2+deb8u1.

We recommend that you upgrade your milkytracker packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"milkytracker", ver:"0.90.85+dfsg-2.2+deb8u1", rls:"DEB8"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);