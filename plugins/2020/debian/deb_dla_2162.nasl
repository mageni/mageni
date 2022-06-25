# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.892162");
  script_version("2020-03-30T03:00:11+0000");
  script_cve_id("CVE-2020-8866");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2020-03-30 09:58:56 +0000 (Mon, 30 Mar 2020)");
  script_tag(name:"creation_date", value:"2020-03-30 03:00:11 +0000 (Mon, 30 Mar 2020)");
  script_name("Debian LTS: Security Advisory for php-horde-form (DLA-2162-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2020/03/msg00036.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-2162-1");
  script_xref(name:"URL", value:"https://bugs.debian.org/955020");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'php-horde-form'
  package(s) announced via the DLA-2162-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A remote code execution vulnerability was discovered in the Form API
component of the Horde Application Framework. An authenticated remote
attacker could use this flaw to upload arbitrary content to an arbitrary
writable location on the server and potentially execute code in the
context of the web server user.");

  script_tag(name:"affected", value:"'php-horde-form' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 8 'Jessie', this problem has been fixed in version
2.0.8-2+deb8u2.

We recommend that you upgrade your php-horde-form packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"php-horde-form", ver:"2.0.8-2+deb8u2", rls:"DEB8"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
