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
  script_oid("1.3.6.1.4.1.25623.1.0.892547");
  script_version("2021-02-07T04:00:17+0000");
  script_cve_id("CVE-2019-13619", "CVE-2019-16319", "CVE-2019-19553", "CVE-2020-11647", "CVE-2020-13164", "CVE-2020-15466", "CVE-2020-25862", "CVE-2020-25863", "CVE-2020-26418", "CVE-2020-26421", "CVE-2020-26575", "CVE-2020-28030", "CVE-2020-7045", "CVE-2020-9428", "CVE-2020-9430", "CVE-2020-9431");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2021-02-08 11:02:13 +0000 (Mon, 08 Feb 2021)");
  script_tag(name:"creation_date", value:"2021-02-07 04:00:17 +0000 (Sun, 07 Feb 2021)");
  script_name("Debian LTS: Security Advisory for wireshark (DLA-2547-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2021/02/msg00008.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-2547-1");
  script_xref(name:"Advisory-ID", value:"DLA-2547-1");
  script_xref(name:"URL", value:"https://bugs.debian.org/958213");
  script_xref(name:"URL", value:"https://bugs.debian.org/974688");
  script_xref(name:"URL", value:"https://bugs.debian.org/974689");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'wireshark'
  package(s) announced via the DLA-2547-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities were fixed in Wireshark, a network sniffer.

CVE-2019-13619

ASN.1 BER and related dissectors crash.

CVE-2019-16319

The Gryphon dissector could go into an infinite loop.

CVE-2019-19553

The CMS dissector could crash.

CVE-2020-7045

The BT ATT dissector could crash.

CVE-2020-9428

The EAP dissector could crash.

CVE-2020-9430

The WiMax DLMAP dissector could crash.

CVE-2020-9431

The LTE RRC dissector could leak memory.

CVE-2020-11647

The BACapp dissector could crash.

CVE-2020-13164

The NFS dissector could crash.

CVE-2020-15466

The GVCP dissector could go into an infinite loop.

CVE-2020-25862

The TCP dissector could crash.

CVE-2020-25863

The MIME Multipart dissector could crash.

CVE-2020-26418

Memory leak in the Kafka protocol dissector.

CVE-2020-26421

Crash in USB HID protocol dissector.

CVE-2020-26575

The Facebook Zero Protocol (aka FBZERO) dissector
could enter an infinite loop.

CVE-2020-28030

The GQUIC dissector could crash.");

  script_tag(name:"affected", value:"'wireshark' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 9 stretch, these problems have been fixed in version
2.6.20-0+deb9u1.

We recommend that you upgrade your wireshark packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"libwireshark-data", ver:"2.6.20-0+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libwireshark-dev", ver:"2.6.20-0+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libwireshark11", ver:"2.6.20-0+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libwireshark8", ver:"2.6.20-0+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libwiretap-dev", ver:"2.6.20-0+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libwiretap6", ver:"2.6.20-0+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libwiretap8", ver:"2.6.20-0+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libwscodecs1", ver:"2.6.20-0+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libwscodecs2", ver:"2.6.20-0+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libwsutil-dev", ver:"2.6.20-0+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libwsutil7", ver:"2.6.20-0+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libwsutil9", ver:"2.6.20-0+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"tshark", ver:"2.6.20-0+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"wireshark", ver:"2.6.20-0+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"wireshark-common", ver:"2.6.20-0+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"wireshark-dev", ver:"2.6.20-0+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"wireshark-doc", ver:"2.6.20-0+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"wireshark-gtk", ver:"2.6.20-0+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"wireshark-qt", ver:"2.6.20-0+deb9u1", rls:"DEB9"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
