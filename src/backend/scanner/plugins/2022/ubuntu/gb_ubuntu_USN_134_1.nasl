# Copyright (C) 2022 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.1.12.2005.134.1");
  script_cve_id("CVE-2005-1160", "CVE-2005-1531", "CVE-2005-1532");
  script_tag(name:"creation_date", value:"2022-08-26 07:43:23 +0000 (Fri, 26 Aug 2022)");
  script_version("2022-08-26T07:43:23+0000");
  script_tag(name:"last_modification", value:"2022-08-26 07:43:23 +0000 (Fri, 26 Aug 2022)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Ubuntu: Security Advisory (USN-134-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU5\.04");

  script_xref(name:"Advisory-ID", value:"USN-134-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-134-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mozilla-firefox' package(s) announced via the USN-134-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that a malicious website could inject arbitrary
scripts into a target site by loading it into a frame and navigating
back to a previous Javascript URL that contained an eval() call. This
could be used to steal cookies or other confidential data from the
target site. If the target site is allowed to raise the install
confirmation dialog in Firefox then this flaw even allowed the
malicious site to execute arbitrary code with the privileges of the
Firefox user. By default only the Mozilla Update site is allowed to
attempt software installation, however, users can permit this for
additional sites. (MFSA 2005-42)

Michael Krax, Georgi Guninski, and L. David Baron found that the
security checks that prevent script injection could be bypassed by
wrapping a javascript: url in another pseudo-protocol like
'view-source:' or 'jar:'. (CAN-2005-1531)

A variant of the attack described in CAN-2005-1160 (see USN-124-1) was
discovered. Additional checks were added to make sure Javascript eval
and Script objects are run with the privileges of the context that
created them, not the potentially elevated privilege of the context
calling them. (CAN-2005-1532)

Note: These flaws also apply to Ubuntu 5.04's Mozilla, and to the
Ubuntu 4.10 versions of Firefox and Mozilla. These will be fixed soon.");

  script_tag(name:"affected", value:"'mozilla-firefox' package(s) on Ubuntu 5.04.");

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

if(release == "UBUNTU5.04") {

  if(!isnull(res = isdpkgvuln(pkg:"mozilla-firefox-dev", ver:"1.0.2-0ubuntu5.3", rls:"UBUNTU5.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mozilla-firefox-dom-inspector", ver:"1.0.2-0ubuntu5.3", rls:"UBUNTU5.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mozilla-firefox-gnome-support", ver:"1.0.2-0ubuntu5.3", rls:"UBUNTU5.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mozilla-firefox", ver:"1.0.2-0ubuntu5.3", rls:"UBUNTU5.04"))) {
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
