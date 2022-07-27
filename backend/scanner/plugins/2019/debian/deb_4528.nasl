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
  script_oid("1.3.6.1.4.1.25623.1.0.704528");
  script_version("2019-09-21T02:00:06+0000");
  script_cve_id("CVE-2019-16159");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2019-09-21 02:00:06 +0000 (Sat, 21 Sep 2019)");
  script_tag(name:"creation_date", value:"2019-09-21 02:00:06 +0000 (Sat, 21 Sep 2019)");
  script_name("Debian Security Advisory DSA 4528-1 (bird - security update)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"URL", value:"https://www.debian.org/security/2019/dsa-4528.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-4528-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'bird'
  package(s) announced via the DSA-4528-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Daniel McCarney discovered that the BIRD internet routing daemon
incorrectly validated RFC 8203 messages in it's BGP daemon, resulting
in a stack buffer overflow.");

  script_tag(name:"affected", value:"'bird' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For the stable distribution (buster), this problem has been fixed in
version 1.6.6-1+deb10u1. In addition this update fixes an incomplete
revocation of privileges and a crash triggerable via the CLI (the latter
two bugs are also fixed in the oldstable distribution (stretch) which is
not affected by
CVE-2019-16159).

We recommend that you upgrade your bird packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"bird", ver:"1.6.6-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"bird-bgp", ver:"1.6.6-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"bird-doc", ver:"1.6.6-1+deb10u1", rls:"DEB10"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
