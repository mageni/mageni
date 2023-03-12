# Copyright (C) 2023 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2014.112");
  script_cve_id("CVE-2014-8500");
  script_tag(name:"creation_date", value:"2023-03-08 12:56:44 +0000 (Wed, 08 Mar 2023)");
  script_version("2023-03-09T10:09:19+0000");
  script_tag(name:"last_modification", value:"2023-03-09 10:09:19 +0000 (Thu, 09 Mar 2023)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_name("Debian: Security Advisory (DLA-112)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB6");

  script_xref(name:"Advisory-ID", value:"DLA-112");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2014/dla-112");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'bind9' package(s) announced via the DLA-112 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update fixes a denial of service vulnerability in BIND, a DNS server.

By making use of maliciously-constructed zones or a rogue server, an attacker could exploit an oversight in the code BIND 9 used to follow delegations in the Domain Name Service, causing BIND to issue unlimited queries in an attempt to follow the delegation.

This can lead to resource exhaustion and denial of service (up to and including termination of the named server process).

For Debian 6 Squeeze, these issues have been fixed in bind9 version 9.7.3.dfsg-1~squeeze13");

  script_tag(name:"affected", value:"'bind9' package(s) on Debian 6.");

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

if(release == "DEB6") {

  if(!isnull(res = isdpkgvuln(pkg:"bind9-doc", ver:"1:9.7.3.dfsg-1~squeeze13", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"bind9-host", ver:"1:9.7.3.dfsg-1~squeeze13", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"bind9", ver:"1:9.7.3.dfsg-1~squeeze13", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"bind9utils", ver:"1:9.7.3.dfsg-1~squeeze13", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dnsutils", ver:"1:9.7.3.dfsg-1~squeeze13", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"host", ver:"1:9.7.3.dfsg-1~squeeze13", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libbind-dev", ver:"1:9.7.3.dfsg-1~squeeze13", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libbind9-60", ver:"1:9.7.3.dfsg-1~squeeze13", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libdns69", ver:"1:9.7.3.dfsg-1~squeeze13", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libisc62", ver:"1:9.7.3.dfsg-1~squeeze13", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libisccc60", ver:"1:9.7.3.dfsg-1~squeeze13", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libisccfg62", ver:"1:9.7.3.dfsg-1~squeeze13", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"liblwres60", ver:"1:9.7.3.dfsg-1~squeeze13", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lwresd", ver:"1:9.7.3.dfsg-1~squeeze13", rls:"DEB6"))) {
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
