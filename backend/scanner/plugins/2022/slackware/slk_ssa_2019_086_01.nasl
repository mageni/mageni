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
  script_oid("1.3.6.1.4.1.25623.1.1.13.2019.086.01");
  script_tag(name:"creation_date", value:"2022-04-21 12:12:27 +0000 (Thu, 21 Apr 2022)");
  script_version("2022-04-26T09:43:38+0000");
  script_tag(name:"last_modification", value:"2022-05-10 10:06:01 +0000 (Tue, 10 May 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Slackware: Security Advisory (SSA:2019-086-01)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Slackware Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/slackware_linux", "ssh/login/slackpack", re:"ssh/login/release=SLK14\.2");

  script_xref(name:"Advisory-ID", value:"SSA:2019-086-01");
  script_xref(name:"URL", value:"http://www.slackware.com/security/viewer.php?l=slackware-security&y=2019&m=slackware-security.427640");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gnutls' package(s) announced via the SSA:2019-086-01 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"New gnutls packages are available for Slackware 14.2 and -current to
fix security issues.


Here are the details from the Slackware 14.2 ChangeLog:
+--------------------------+
patches/packages/gnutls-3.6.7-i586-1_slack14.2.txz: Upgraded.
 Fixes security issues:
 libgnutls, gnutls tools: Every gnutls_free() will automatically set
 the free'd pointer to NULL. This prevents possible use-after-free and
 double free issues. Use-after-free will be turned into NULL dereference.
 The counter-measure does not extend to applications using gnutls_free().
 libgnutls: Fixed a memory corruption (double free) vulnerability in the
 certificate verification API. Reported by Tavis Ormandy, addressed with
 the change above. [GNUTLS-SA-2019-03-27, #694]
 libgnutls: Fixed an invalid pointer access via malformed TLS1.3 async
 messages, Found using tlsfuzzer. [GNUTLS-SA-2019-03-27, #704]
 libgnutls: enforce key usage limitations on certificates more actively.
 Previously we would enforce it for TLS1.2 protocol, now we enforce it
 even when TLS1.3 is negotiated, or on client certificates as well. When
 an inappropriate for TLS1.3 certificate is seen on the credentials
 structure GnuTLS will disable TLS1.3 support for that session (#690).
 libgnutls: enforce the equality of the two signature parameters fields
 in a certificate. We were already enforcing the signature algorithm,
 but there was a bug in parameter checking code.
 (* Security fix *)
+--------------------------+");

  script_tag(name:"affected", value:"'gnutls' package(s) on Slackware 14.2, Slackware current.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-slack.inc");


res = "";
report = "";

if(!isnull(res = isslkpkgvuln(pkg:"gnutls", ver:"3.6.7-i586-1_slack14.2", rls:"SLK14.2"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"gnutls", ver:"3.6.7-x86_64-1_slack14.2", rls:"SLK14.2"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}
exit(0);
