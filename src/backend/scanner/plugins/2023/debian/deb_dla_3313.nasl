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
  script_oid("1.3.6.1.4.1.25623.1.0.893313");
  script_version("2023-02-09T10:17:23+0000");
  script_cve_id("CVE-2022-4345", "CVE-2023-0411", "CVE-2023-0412", "CVE-2023-0413", "CVE-2023-0415", "CVE-2023-0417");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-02-09 10:17:23 +0000 (Thu, 09 Feb 2023)");
  script_tag(name:"creation_date", value:"2023-02-09 02:00:24 +0000 (Thu, 09 Feb 2023)");
  script_name("Debian LTS: Security Advisory for wireshark (DLA-3313-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2023/02/msg00007.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-3313-1");
  script_xref(name:"Advisory-ID", value:"DLA-3313-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'wireshark'
  package(s) announced via the DLA-3313-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple security vulnerabilities have been discovered in Wireshark, a
network traffic analyzer. An attacker could cause a denial of service
(infinite loop or application crash) via packet injection or a crafted
capture file.

CVE-2022-4345

Infinite loops in the BPv6, OpenFlow, and Kafka protocol dissectors in
Wireshark 4.0.0 to 4.0.1 and 3.6.0 to 3.6.9 allows denial of service via
packet injection or crafted capture file

CVE-2023-0411

Excessive loops in multiple dissectors in Wireshark 4.0.0 to 4.0.2 and
3.6.0 to 3.6.10 and allows denial of service via packet injection or
crafted capture file

CVE-2023-0412

TIPC dissector crash in Wireshark 4.0.0 to 4.0.2 and 3.6.0 to 3.6.10 and
allows denial of service via packet injection or crafted capture file

CVE-2023-0413

Dissection engine bug in Wireshark 4.0.0 to 4.0.2 and 3.6.0 to 3.6.10
and allows denial of service via packet injection or crafted capture
file

CVE-2023-0415

iSCSI dissector crash in Wireshark 4.0.0 to 4.0.2 and 3.6.0 to 3.6.10
and allows denial of service via packet injection or crafted capture
file

CVE-2023-0417

Memory leak in the NFS dissector in Wireshark 4.0.0 to 4.0.2 and 3.6.0
to 3.6.10 and allows denial of service via packet injection or crafted
capture file");

  script_tag(name:"affected", value:"'wireshark' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 10 buster, these problems have been fixed in version
2.6.20-0+deb10u5.

We recommend that you upgrade your wireshark packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"libwireshark-data", ver:"2.6.20-0+deb10u5", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libwireshark-dev", ver:"2.6.20-0+deb10u5", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libwireshark11", ver:"2.6.20-0+deb10u5", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libwiretap-dev", ver:"2.6.20-0+deb10u5", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libwiretap8", ver:"2.6.20-0+deb10u5", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libwscodecs2", ver:"2.6.20-0+deb10u5", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libwsutil-dev", ver:"2.6.20-0+deb10u5", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libwsutil9", ver:"2.6.20-0+deb10u5", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"tshark", ver:"2.6.20-0+deb10u5", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"wireshark", ver:"2.6.20-0+deb10u5", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"wireshark-common", ver:"2.6.20-0+deb10u5", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"wireshark-dev", ver:"2.6.20-0+deb10u5", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"wireshark-doc", ver:"2.6.20-0+deb10u5", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"wireshark-gtk", ver:"2.6.20-0+deb10u5", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"wireshark-qt", ver:"2.6.20-0+deb10u5", rls:"DEB10"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
