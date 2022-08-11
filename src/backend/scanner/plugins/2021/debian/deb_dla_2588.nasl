# Copyright (C) 2021 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.892588");
  script_version("2021-03-11T04:00:08+0000");
  script_cve_id("CVE-2021-20234", "CVE-2021-20235");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2021-03-11 11:26:33 +0000 (Thu, 11 Mar 2021)");
  script_tag(name:"creation_date", value:"2021-03-11 04:00:08 +0000 (Thu, 11 Mar 2021)");
  script_name("Debian LTS: Security Advisory for zeromq3 (DLA-2588-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2021/03/msg00011.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-2588-1");
  script_xref(name:"Advisory-ID", value:"DLA-2588-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'zeromq3'
  package(s) announced via the DLA-2588-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Two security issues have been detected in zeromq3.

CVE-2021-20234

Memory leak in client induced by malicious server(s) without CURVE/ZAP.

From issue description [1].
When a pipe processes a delimiter and is already not in active state but
still has an unfinished message, the message is leaked.

CVE-2021-20235

Heap overflow when receiving malformed ZMTP v1 packets.

From issue description [2].
The static allocator was implemented to shrink its recorded size similarly
to the shared allocator. But it does not need to, and it should not,
because unlike the shared one the static allocator always uses a static
buffer, with a size defined by the ZMQ_IN_BATCH_SIZE socket option
(default 8192), so changing the size opens the library to heap overflows.
The static allocator is used only with ZMTP v1 peers.

[1]");

  script_tag(name:"affected", value:"'zeromq3' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 9 stretch, these problems have been fixed in version
4.2.1-4+deb9u4.

We recommend that you upgrade your zeromq3 packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"libzmq3-dev", ver:"4.2.1-4+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libzmq5", ver:"4.2.1-4+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libzmq5-dbg", ver:"4.2.1-4+deb9u4", rls:"DEB9"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
