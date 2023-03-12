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
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2016.455");
  script_cve_id("CVE-2014-2286", "CVE-2014-4046", "CVE-2014-6610", "CVE-2014-8412", "CVE-2014-8418", "CVE-2015-3008");
  script_tag(name:"creation_date", value:"2023-03-08 12:56:44 +0000 (Wed, 08 Mar 2023)");
  script_version("2023-03-09T10:09:19+0000");
  script_tag(name:"last_modification", value:"2023-03-09 10:09:19 +0000 (Thu, 09 Mar 2023)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DLA-455)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");

  script_xref(name:"Advisory-ID", value:"DLA-455");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2016/dla-455");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'asterisk' package(s) announced via the DLA-455 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"CVE-2014-6610

Asterisk Open Source 11.x before 11.12.1 and 12.x before 12.5.1 and Certified Asterisk 11.6 before 11.6-cert6, when using the res_fax_spandsp module, allows remote authenticated users to cause a denial of service (crash) via an out of call message, which is not properly handled in the ReceiveFax dialplan application.

CVE-2014-4046

Asterisk Open Source 11.x before 11.10.1 and 12.x before 12.3.1 and Certified Asterisk 11.6 before 11.6-cert3 allows remote authenticated Manager users to execute arbitrary shell commands via a MixMonitor action.

CVE-2014-2286

main/http.c in Asterisk Open Source 1.8.x before 1.8.26.1, 11.8.x before 11.8.1, and 12.1.x before 12.1.1, and Certified Asterisk 1.8.x before 1.8.15-cert5 and 11.6 before 11.6-cert2, allows remote attackers to cause a denial of service (stack consumption) and possibly execute arbitrary code via an HTTP request with a large number of Cookie headers.

CVE-2014-8412

The (1) VoIP channel drivers, (2) DUNDi, and (3) Asterisk Manager Interface (AMI) in Asterisk Open Source 1.8.x before 1.8.32.1, 11.x before 11.14.1, 12.x before 12.7.1, and 13.x before 13.0.1 and Certified Asterisk 1.8.28 before 1.8.28-cert3 and 11.6 before 11.6-cert8 allows remote attackers to bypass the ACL restrictions via a packet with a source IP that does not share the address family as the first ACL entry.

CVE-2014-8418

The DB dialplan function in Asterisk Open Source 1.8.x before 1.8.32, 11.x before 11.1.4.1, 12.x before 12.7.1, and 13.x before 13.0.1 and Certified Asterisk 1.8 before 1.8.28-cert8 and 11.6 before 11.6-cert8 allows remote authenticated users to gain privileges via a call from an external protocol, as demonstrated by the AMI protocol.

CVE-2015-3008

Asterisk Open Source 1.8 before 1.8.32.3, 11.x before 11.17.1, 12.x before 12.8.2, and 13.x before 13.3.2 and Certified Asterisk 1.8.28 before 1.8.28-cert5, 11.6 before 11.6-cert11, and 13.1 before 13.1-cert2, when registering a SIP TLS device, does not properly handle a null byte in a domain name in the subject's Common Name (CN) field of an X.509 certificate, which allows man-in-the-middle attackers to spoof arbitrary SSL servers via a crafted certificate issued by a legitimate Certification Authority.

For Debian 7 Wheezy, these issues have been fixed in asterisk version 1:1.8.13.1~dfsg1-3+deb7u4");

  script_tag(name:"affected", value:"'asterisk' package(s) on Debian 7.");

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

if(release == "DEB7") {

  if(!isnull(res = isdpkgvuln(pkg:"asterisk-config", ver:"1:1.8.13.1~dfsg1-3+deb7u4", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"asterisk-dahdi", ver:"1:1.8.13.1~dfsg1-3+deb7u4", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"asterisk-dbg", ver:"1:1.8.13.1~dfsg1-3+deb7u4", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"asterisk-dev", ver:"1:1.8.13.1~dfsg1-3+deb7u4", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"asterisk-doc", ver:"1:1.8.13.1~dfsg1-3+deb7u4", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"asterisk-mobile", ver:"1:1.8.13.1~dfsg1-3+deb7u4", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"asterisk-modules", ver:"1:1.8.13.1~dfsg1-3+deb7u4", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"asterisk-mp3", ver:"1:1.8.13.1~dfsg1-3+deb7u4", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"asterisk-mysql", ver:"1:1.8.13.1~dfsg1-3+deb7u4", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"asterisk-ooh323", ver:"1:1.8.13.1~dfsg1-3+deb7u4", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"asterisk-voicemail-imapstorage", ver:"1:1.8.13.1~dfsg1-3+deb7u4", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"asterisk-voicemail-odbcstorage", ver:"1:1.8.13.1~dfsg1-3+deb7u4", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"asterisk-voicemail", ver:"1:1.8.13.1~dfsg1-3+deb7u4", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"asterisk", ver:"1:1.8.13.1~dfsg1-3+deb7u4", rls:"DEB7"))) {
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
