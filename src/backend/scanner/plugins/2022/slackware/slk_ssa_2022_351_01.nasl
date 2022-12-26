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
  script_oid("1.3.6.1.4.1.25623.1.1.13.2022.351.01");
  script_cve_id("CVE-2022-37966", "CVE-2022-37967", "CVE-2022-38023", "CVE-2022-45141");
  script_tag(name:"creation_date", value:"2022-12-19 04:21:54 +0000 (Mon, 19 Dec 2022)");
  script_version("2022-12-19T04:21:54+0000");
  script_tag(name:"last_modification", value:"2022-12-19 04:21:54 +0000 (Mon, 19 Dec 2022)");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-11-10 14:50:00 +0000 (Thu, 10 Nov 2022)");

  script_name("Slackware: Security Advisory (SSA:2022-351-01)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Slackware Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/slackware_linux", "ssh/login/slackpack", re:"ssh/login/release=SLK(15\.0|current)");

  script_xref(name:"Advisory-ID", value:"SSA:2022-351-01");
  script_xref(name:"URL", value:"http://www.slackware.com/security/viewer.php?l=slackware-security&y=2022&m=slackware-security.501177");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2022-37966");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2022-37967");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2022-38023");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2022-45141");
  script_xref(name:"URL", value:"https://www.samba.org/samba/security/CVE-2022-37966.html");
  script_xref(name:"URL", value:"https://www.samba.org/samba/security/CVE-2022-37967.html");
  script_xref(name:"URL", value:"https://www.samba.org/samba/security/CVE-2022-38023.html");
  script_xref(name:"URL", value:"https://www.samba.org/samba/security/CVE-2022-45141.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'samba' package(s) announced via the SSA:2022-351-01 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"New samba packages are available for Slackware 15.0 and -current to
fix security issues.


Here are the details from the Slackware 15.0 ChangeLog:
+--------------------------+
patches/packages/samba-4.15.13-i586-1_slack15.0.txz: Upgraded.
 This update fixes security issues:
 This is the Samba CVE for the Windows Kerberos RC4-HMAC Elevation of
 Privilege Vulnerability disclosed by Microsoft on Nov 8 2022.
 A Samba Active Directory DC will issue weak rc4-hmac session keys for
 use between modern clients and servers despite all modern Kerberos
 implementations supporting the aes256-cts-hmac-sha1-96 cipher.
 On Samba Active Directory DCs and members
 'kerberos encryption types = legacy'
 would force rc4-hmac as a client even if the server supports
 aes128-cts-hmac-sha1-96 and/or aes256-cts-hmac-sha1-96.
 This is the Samba CVE for the Windows Kerberos Elevation of Privilege
 Vulnerability disclosed by Microsoft on Nov 8 2022.
 A service account with the special constrained delegation permission
 could forge a more powerful ticket than the one it was presented with.
 The 'RC4' protection of the NetLogon Secure channel uses the same
 algorithms as rc4-hmac cryptography in Kerberos, and so must also be
 assumed to be weak.
 Since the Windows Kerberos RC4-HMAC Elevation of Privilege Vulnerability
 was disclosed by Microsoft on Nov 8 2022 and per RFC8429 it is assumed
 that rc4-hmac is weak, Vulnerable Samba Active Directory DCs will issue
 rc4-hmac encrypted tickets despite the target server supporting better
 encryption (eg aes256-cts-hmac-sha1-96).
 Note that there are several important behavior changes included in this
 release, which may cause compatibility problems interacting with system
 still expecting the former behavior.
 Please read the advisories of CVE-2022-37966, CVE-2022-37967 and
 CVE-2022-38023 carefully!
 For more information, see:
 [link moved to references]
 [link moved to references]
 [link moved to references]
 [link moved to references]
 [link moved to references]
 [link moved to references]
 [link moved to references]
 [link moved to references]
 (* Security fix *)
+--------------------------+");

  script_tag(name:"affected", value:"'samba' package(s) on Slackware 15.0, Slackware current.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-slack.inc");

release = slk_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "SLK15.0") {

  if(!isnull(res = isslkpkgvuln(pkg:"samba", ver:"4.15.13-i586-1_slack15.0", rls:"SLK15.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"samba", ver:"4.15.13-x86_64-1_slack15.0", rls:"SLK15.0"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLKcurrent") {

  if(!isnull(res = isslkpkgvuln(pkg:"samba", ver:"4.17.4-i586-1", rls:"SLKcurrent"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"samba", ver:"4.17.4-x86_64-1", rls:"SLKcurrent"))) {
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
