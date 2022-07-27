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
  script_oid("1.3.6.1.4.1.25623.1.1.13.2017.291.02");
  script_cve_id("CVE-2017-13077", "CVE-2017-13078", "CVE-2017-13079", "CVE-2017-13080", "CVE-2017-13081", "CVE-2017-13082", "CVE-2017-13084", "CVE-2017-13086", "CVE-2017-13087", "CVE-2017-13088");
  script_tag(name:"creation_date", value:"2022-04-21 12:12:27 +0000 (Thu, 21 Apr 2022)");
  script_version("2022-05-05T07:49:10+0000");
  script_tag(name:"last_modification", value:"2022-05-10 10:06:01 +0000 (Tue, 10 May 2022)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");

  script_name("Slackware: Security Advisory (SSA:2017-291-02)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Slackware Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/slackware_linux", "ssh/login/slackpack", re:"ssh/login/release=SLK(14\.0|14\.1|14\.2)");

  script_xref(name:"Advisory-ID", value:"SSA:2017-291-02");
  script_xref(name:"URL", value:"http://www.slackware.com/security/viewer.php?l=slackware-security&y=2017&m=slackware-security.592891");
  script_xref(name:"URL", value:"https://w1.fi/security/2017-1/wpa-packet-number-reuse-with-replayed-messages.txt");
  script_xref(name:"URL", value:"https://www.krackattacks.com/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'wpa_supplicant' package(s) announced via the SSA:2017-291-02 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"New wpa_supplicant packages are available for Slackware 14.0, 14.1, 14.2,
and -current to fix security issues.


Here are the details from the Slackware 14.2 ChangeLog:
+--------------------------+
patches/packages/wpa_supplicant-2.6-i586-1_slack14.2.txz: Upgraded.
 This update includes patches to mitigate the WPA2 protocol issues known
 as 'KRACK' (Key Reinstallation AttaCK), which may be used to decrypt data,
 hijack TCP connections, and to forge and inject packets. This is the
 list of vulnerabilities that are addressed here:
 CVE-2017-13077: Reinstallation of the pairwise encryption key (PTK-TK) in the
 4-way handshake.
 CVE-2017-13078: Reinstallation of the group key (GTK) in the 4-way handshake.
 CVE-2017-13079: Reinstallation of the integrity group key (IGTK) in the 4-way
 handshake.
 CVE-2017-13080: Reinstallation of the group key (GTK) in the group key
 handshake.
 CVE-2017-13081: Reinstallation of the integrity group key (IGTK) in the group
 key handshake.
 CVE-2017-13082: Accepting a retransmitted Fast BSS Transition (FT)
 Reassociation Request and reinstalling the pairwise encryption key (PTK-TK)
 while processing it.
 CVE-2017-13084: Reinstallation of the STK key in the PeerKey handshake.
 CVE-2017-13086: reinstallation of the Tunneled Direct-Link Setup (TDLS)
 PeerKey (TPK) key in the TDLS handshake.
 CVE-2017-13087: reinstallation of the group key (GTK) when processing a
 Wireless Network Management (WNM) Sleep Mode Response frame.
 CVE-2017-13088: reinstallation of the integrity group key (IGTK) when
 processing a Wireless Network Management (WNM) Sleep Mode Response frame.
 For more information, see:
 [link moved to references]
 [link moved to references]
 [link moved to references]
 [link moved to references]
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

  script_tag(name:"affected", value:"'wpa_supplicant' package(s) on Slackware 14.0, Slackware 14.1, Slackware 14.2, Slackware current.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-slack.inc");


res = "";
report = "";

if(!isnull(res = isslkpkgvuln(pkg:"wpa_supplicant", ver:"2.6-i486-1_slack14.0", rls:"SLK14.0"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"wpa_supplicant", ver:"2.6-x86_64-1_slack14.0", rls:"SLK14.0"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"wpa_supplicant", ver:"2.6-i486-1_slack14.1", rls:"SLK14.1"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"wpa_supplicant", ver:"2.6-x86_64-1_slack14.1", rls:"SLK14.1"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"wpa_supplicant", ver:"2.6-i586-1_slack14.2", rls:"SLK14.2"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"wpa_supplicant", ver:"2.6-x86_64-1_slack14.2", rls:"SLK14.2"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}
exit(0);
