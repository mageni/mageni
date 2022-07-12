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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2014.0034");
  script_cve_id("CVE-2012-6152", "CVE-2013-6477", "CVE-2013-6478", "CVE-2013-6479", "CVE-2013-6481", "CVE-2013-6482", "CVE-2013-6483", "CVE-2013-6484", "CVE-2013-6485", "CVE-2013-6487", "CVE-2013-6489", "CVE-2013-6490", "CVE-2014-0020");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2014-03-08 05:11:00 +0000 (Sat, 08 Mar 2014)");

  script_name("Mageia: Security Advisory (MGASA-2014-0034)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA3");

  script_xref(name:"Advisory-ID", value:"MGASA-2014-0034");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2014-0034.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=12468");
  script_xref(name:"URL", value:"http://pidgin.im/news/security/?id=70");
  script_xref(name:"URL", value:"http://pidgin.im/news/security/?id=71");
  script_xref(name:"URL", value:"http://pidgin.im/news/security/?id=72");
  script_xref(name:"URL", value:"http://pidgin.im/news/security/?id=73");
  script_xref(name:"URL", value:"http://pidgin.im/news/security/?id=74");
  script_xref(name:"URL", value:"http://pidgin.im/news/security/?id=75");
  script_xref(name:"URL", value:"http://pidgin.im/news/security/?id=76");
  script_xref(name:"URL", value:"http://pidgin.im/news/security/?id=77");
  script_xref(name:"URL", value:"http://pidgin.im/news/security/?id=78");
  script_xref(name:"URL", value:"http://pidgin.im/news/security/?id=79");
  script_xref(name:"URL", value:"http://pidgin.im/news/security/?id=80");
  script_xref(name:"URL", value:"http://pidgin.im/news/security/?id=82");
  script_xref(name:"URL", value:"http://pidgin.im/news/security/?id=83");
  script_xref(name:"URL", value:"http://pidgin.im/news/security/?id=84");
  script_xref(name:"URL", value:"http://pidgin.im/news/security/?id=85");
  script_xref(name:"URL", value:"https://developer.pidgin.im/wiki/ChangeLog");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'pidgin' package(s) announced via the MGASA-2014-0034 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Many places in the Yahoo! protocol plugin assumed incoming strings were
UTF-8 and failed to transcode from non-UTF-8 encodings. This can lead to a
crash when receiving strings that aren't UTF-8 (CVE-2012-6152).

A remote XMPP user can trigger a crash on some systems by sending a
message with a timestamp in the distant future (CVE-2013-6477).

libX11 forcefully exits causing a crash when Pidgin tries to create an
exceptionally wide tooltip window when hovering the pointer over a long
URL (CVE-2013-6478).

A malicious server or man-in-the-middle could send a malformed HTTP
response that could lead to a crash (CVE-2013-6479).

The Yahoo! protocol plugin failed to validate a length field before trying
to read from a buffer, which could result in reading past the end of the
buffer which could cause a crash when reading a P2P message
(CVE-2013-6481).

NULL pointer dereferences in the MSN protocol plugin due to a malformed
Content-Length header, or a malicious server or man-in-the-middle sending
a specially crafted OIM data XML response or SOAP response
(CVE-2013-6482).

The XMPP protocol plugin failed to ensure that iq replies came from the
person they were sent to. A remote user could send a spoofed iq reply and
attempt to guess the iq id. This could allow an attacker to inject fake
data or trigger a null pointer dereference (CVE-2013-6483).

Incorrect error handling when reading the response from a STUN server
could lead to a crash (CVE-2013-6484).

A malicious server or man-in-the-middle could cause a buffer overflow by
sending a malformed HTTP response with chunked Transfer-Encoding with
invalid chunk sizes (CVE-2013-6485).

A malicious server or man-in-the-middle could send a large value for
Content-Length and cause an integer overflow which could lead to a buffer
overflow in Gadu-Gadu HTTP parsing (CVE-2013-6487).

A specially crafted emoticon value could cause an integer overflow which
could lead to a buffer overflow in MXit emoticon parsing (CVE-2013-6489).

A Content-Length of -1 could lead to a buffer overflow in SIMPLE header
parsing (CVE-2013-6490).

A malicious server or man-in-the-middle could trigger a crash in IRC
argument parsing in libpurple by sending a message with fewer than
expected arguments
(CVE-2014-0020).");

  script_tag(name:"affected", value:"'pidgin' package(s) on Mageia 3.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "MAGEIA3") {

  if(!isnull(res = isrpmvuln(pkg:"finch", rpm:"finch~2.10.9~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64finch0", rpm:"lib64finch0~2.10.9~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64purple-devel", rpm:"lib64purple-devel~2.10.9~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64purple0", rpm:"lib64purple0~2.10.9~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfinch0", rpm:"libfinch0~2.10.9~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpurple-devel", rpm:"libpurple-devel~2.10.9~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpurple0", rpm:"libpurple0~2.10.9~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pidgin", rpm:"pidgin~2.10.9~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pidgin-bonjour", rpm:"pidgin-bonjour~2.10.9~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pidgin-client", rpm:"pidgin-client~2.10.9~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pidgin-i18n", rpm:"pidgin-i18n~2.10.9~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pidgin-meanwhile", rpm:"pidgin-meanwhile~2.10.9~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pidgin-perl", rpm:"pidgin-perl~2.10.9~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pidgin-plugins", rpm:"pidgin-plugins~2.10.9~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pidgin-silc", rpm:"pidgin-silc~2.10.9~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pidgin-tcl", rpm:"pidgin-tcl~2.10.9~1.mga3", rls:"MAGEIA3"))) {
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
