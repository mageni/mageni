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
  script_oid("1.3.6.1.4.1.25623.1.0.891671");
  script_version("2019-04-01T07:47:16+0000");
  script_cve_id("CVE-2018-4056", "CVE-2018-4058", "CVE-2018-4059");
  script_name("Debian LTS Advisory ([SECURITY] [DLA 1671-1] coturn security update)");
  script_tag(name:"last_modification", value:"2019-04-01 07:47:16 +0000 (Mon, 01 Apr 2019)");
  script_tag(name:"creation_date", value:"2019-02-11 00:00:00 +0100 (Mon, 11 Feb 2019)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2019/02/msg00017.html");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");
  script_tag(name:"affected", value:"coturn on Debian Linux");
  script_tag(name:"solution", value:"For Debian 8 'Jessie', these problems have been fixed in version
4.2.1.2-1+deb8u1.

We recommend that you upgrade your coturn packages.");
  script_tag(name:"summary", value:"Multiple vulnerabilities were discovered in coTURN, a TURN and STUN server for
VoIP.

CVE-2018-4056

An SQL injection vulnerability was discovered in the coTURN administrator
web portal. As the administration web interface is shared with the
production, it is unfortunately not possible to easily filter outside
access and this security update completely disables the web interface. Users
should use the local, command line interface instead.

CVE-2018-4058

Default configuration enables unsafe loopback forwarding. A remote attacker
with access to the TURN interface can use this vulnerability to gain access
to services that should be local only.

CVE-2018-4059

Default configuration uses an empty password for the local command line
administration interface. An attacker with access to the local console
(either a local attacker or a remote attacker taking advantage of
CVE-2018-4058) could escalade privileges to administrator of the coTURN
server.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"coturn", ver:"4.2.1.2-1+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if (__pkg_match) {
  exit(99);
}