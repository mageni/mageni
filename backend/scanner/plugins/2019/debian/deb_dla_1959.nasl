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
  script_oid("1.3.6.1.4.1.25623.1.0.891959");
  script_version("2019-10-15T02:00:09+0000");
  script_cve_id("CVE-2016-10894");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2019-10-15 02:00:09 +0000 (Tue, 15 Oct 2019)");
  script_tag(name:"creation_date", value:"2019-10-15 02:00:09 +0000 (Tue, 15 Oct 2019)");
  script_name("Debian LTS Advisory ([SECURITY] [DLA 1959-1] xtrlock security update)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2019/10/msg00019.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-1959-1");
  script_xref(name:"URL", value:"https://bugs.debian.org/830726");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'xtrlock'
  package(s) announced via the DSA-1959-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that multitouch devices were not being disabled
by the 'xtrlock' screen locking utility.

xtrlock did not block multitouch events so an attacker could still
input and thus control various programs such as Chromium, etc. via
so-called 'multitouch' events including pan scrolling, 'pinch and
zoom' or even being able to provide regular mouse clicks by
depressing the touchpad once and then clicking with a secondary
finger.");

  script_tag(name:"affected", value:"'xtrlock' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 8 'Jessie', this issue has been fixed in xtrlock version
2.6+deb8u1. However, this fix does not the situation where an
attacker plugs in a multitouch device *after* the screen has been
locked. For more information on this, please see:

We recommend that you upgrade your xtrlock packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"xtrlock", ver:"2.6+deb8u1", rls:"DEB8"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
