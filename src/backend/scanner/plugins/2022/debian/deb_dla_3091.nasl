# Copyright (C) 2022 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.893091");
  script_version("2022-09-05T08:41:13+0000");
  script_cve_id("CVE-2022-31001", "CVE-2022-31002", "CVE-2022-31003");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2022-09-05 08:41:13 +0000 (Mon, 05 Sep 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-06-09 13:42:00 +0000 (Thu, 09 Jun 2022)");
  script_tag(name:"creation_date", value:"2022-09-03 01:00:28 +0000 (Sat, 03 Sep 2022)");
  script_name("Debian LTS: Security Advisory for sofia-sip (DLA-3091-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2022/09/msg00001.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-3091-1");
  script_xref(name:"Advisory-ID", value:"DLA-3091-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'sofia-sip'
  package(s) announced via the DLA-3091-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities have been discovered in the sofia-sip, a
SIP user-agent library.

CVE-2022-31001

An attacker can send a message with evil sdp to FreeSWITCH, which
will make `n` bigger and trigger out-of-bound access and may cause
crash

CVE-2022-31002

An attacker can send a message with evil sdp to FreeSWITCH, which
may cause crash.This type of crash is caused by url ending with %,
the craft message looks like this.

CVE-2022-31003

When parsing each line of a sdp message, `rest = record + 2` will
access the memory behind `\0` and cause an out-of-bounds write.
An attacker can send a message with evil sdp to FreeSWITCH,
causing a crash or more serious consequence, such as remote code
execution.");

  script_tag(name:"affected", value:"'sofia-sip' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 10 buster, these problems have been fixed in version
1.12.11+20110422.1-2.1+deb10u1.

We recommend that you upgrade your sofia-sip packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"libsofia-sip-ua-dev", ver:"1.12.11+20110422.1-2.1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libsofia-sip-ua-glib-dev", ver:"1.12.11+20110422.1-2.1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libsofia-sip-ua-glib3", ver:"1.12.11+20110422.1-2.1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libsofia-sip-ua0", ver:"1.12.11+20110422.1-2.1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"sofia-sip-bin", ver:"1.12.11+20110422.1-2.1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"sofia-sip-doc", ver:"1.12.11+20110422.1-2.1+deb10u1", rls:"DEB10"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
