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
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2015.198");
  script_cve_id("CVE-2014-6422", "CVE-2014-6423", "CVE-2014-6428", "CVE-2014-6429", "CVE-2014-6430", "CVE-2014-6431", "CVE-2014-6432", "CVE-2014-8710", "CVE-2014-8711", "CVE-2014-8712", "CVE-2014-8713", "CVE-2014-8714", "CVE-2015-0562", "CVE-2015-0563", "CVE-2015-0564", "CVE-2015-2188", "CVE-2015-2191");
  script_tag(name:"creation_date", value:"2023-03-08 12:56:44 +0000 (Wed, 08 Mar 2023)");
  script_version("2023-03-09T10:09:19+0000");
  script_tag(name:"last_modification", value:"2023-03-09 10:09:19 +0000 (Thu, 09 Mar 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_name("Debian: Security Advisory (DLA-198)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB6");

  script_xref(name:"Advisory-ID", value:"DLA-198");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2015/dla-198");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'wireshark' package(s) announced via the DLA-198 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities were discovered in the Squeeze's Wireshark version:

CVE-2015-2188 The WCP dissector could crash

CVE-2015-0564 Wireshark could crash while decypting TLS/SSL sessions

CVE-2015-0562 The DEC DNA Routing Protocol dissector could crash

CVE-2014-8714 TN5250 infinite loops

CVE-2014-8713 NCP crashes

CVE-2014-8712 NCP crashes

CVE-2014-8711 AMQP crash

CVE-2014-8710 SigComp UDVM buffer overflow

CVE-2014-6432 Sniffer file parser crash

CVE-2014-6431 Sniffer file parser crash

CVE-2014-6430 Sniffer file parser crash

CVE-2014-6429 Sniffer file parser crash

CVE-2014-6428 SES dissector crash

CVE-2014-6423 MEGACO dissector infinite loop

CVE-2014-6422 RTP dissector crash

Since back-porting upstream patches to 1.2.11-6+squeeze15 did not fix all the outstanding issues and some issues are not even tracked publicly the LTS Team decided to sync squeeze-lts's wireshark package with wheezy-security to provide the best possible security support.

Note that upgrading Wireshark from 1.2.x to 1.8.x introduces several backward-incompatible changes in package structure, shared library API/ABI, availability of dissectors and in syntax of command line parameters.");

  script_tag(name:"affected", value:"'wireshark' package(s) on Debian 6.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libwireshark-data", ver:"1.8.2-5wheezy15~deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libwireshark-dev", ver:"1.8.2-5wheezy15~deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libwireshark2", ver:"1.8.2-5wheezy15~deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libwiretap-dev", ver:"1.8.2-5wheezy15~deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libwiretap2", ver:"1.8.2-5wheezy15~deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libwsutil-dev", ver:"1.8.2-5wheezy15~deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libwsutil2", ver:"1.8.2-5wheezy15~deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"tshark", ver:"1.8.2-5wheezy15~deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"wireshark-common", ver:"1.8.2-5wheezy15~deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"wireshark-dbg", ver:"1.8.2-5wheezy15~deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"wireshark-dev", ver:"1.8.2-5wheezy15~deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"wireshark-doc", ver:"1.8.2-5wheezy15~deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"wireshark", ver:"1.8.2-5wheezy15~deb6u1", rls:"DEB6"))) {
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
