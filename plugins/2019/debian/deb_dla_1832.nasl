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
  script_oid("1.3.6.1.4.1.25623.1.0.891832");
  script_version("2019-06-25T02:00:09+0000");
  script_cve_id("CVE-2019-10161", "CVE-2019-10167");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2019-06-25 02:00:09 +0000 (Tue, 25 Jun 2019)");
  script_tag(name:"creation_date", value:"2019-06-25 02:00:09 +0000 (Tue, 25 Jun 2019)");
  script_name("Debian LTS Advisory ([SECURITY] [DLA 1832-1] libvirt security update)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2019/06/msg00020.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-1832-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libvirt'
  package(s) announced via the DSA-1832-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Two vulnerabilities were discovered in libvirt, an abstraction API
for different underlying virtualisation mechanisms provided by the
kernel, etc.

  * CVE-2019-10161: Prevent an vulnerability where readonly clients
could use the API to specify an arbitrary path which would be
accessed with the permissions of the libvirtd process. An attacker
with access to the libvirtd socket could use this to probe the
existence of arbitrary files, cause a denial of service or
otherwise cause libvirtd to execute arbitrary programs.

  * CVE-2019-10167: Prevent an arbitrary code execution vulnerability
via the API where a user-specified binary used to probe the
domain's capabilities. read-only clients could specify an
arbitrary path for this argument, causing libvirtd to execute a
crafted executable with its own privileges.");

  script_tag(name:"affected", value:"'libvirt' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 8 'Jessie', these issues have been fixed in libvirt
version 1.2.9-9+deb8u7.

We recommend that you upgrade your libvirt packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"libvirt-bin", ver:"1.2.9-9+deb8u7", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libvirt-clients", ver:"1.2.9-9+deb8u7", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libvirt-daemon", ver:"1.2.9-9+deb8u7", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libvirt-daemon-system", ver:"1.2.9-9+deb8u7", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libvirt-dev", ver:"1.2.9-9+deb8u7", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libvirt-doc", ver:"1.2.9-9+deb8u7", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libvirt-sanlock", ver:"1.2.9-9+deb8u7", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libvirt0", ver:"1.2.9-9+deb8u7", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libvirt0-dbg", ver:"1.2.9-9+deb8u7", rls:"DEB8"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);