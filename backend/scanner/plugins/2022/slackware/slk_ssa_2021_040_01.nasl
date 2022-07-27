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
  script_oid("1.3.6.1.4.1.25623.1.1.13.2021.040.01");
  script_cve_id("CVE-2020-25681", "CVE-2020-25682", "CVE-2020-25683", "CVE-2020-25684", "CVE-2020-25685", "CVE-2020-25686", "CVE-2020-25687");
  script_tag(name:"creation_date", value:"2022-04-21 12:12:27 +0000 (Thu, 21 Apr 2022)");
  script_version("2022-05-05T07:49:10+0000");
  script_tag(name:"last_modification", value:"2022-05-10 10:06:01 +0000 (Tue, 10 May 2022)");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-03-26 18:23:00 +0000 (Fri, 26 Mar 2021)");

  script_name("Slackware: Security Advisory (SSA:2021-040-01)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Slackware Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/slackware_linux", "ssh/login/slackpack", re:"ssh/login/release=SLK(14\.0|14\.1|14\.2)");

  script_xref(name:"Advisory-ID", value:"SSA:2021-040-01");
  script_xref(name:"URL", value:"http://www.slackware.com/security/viewer.php?l=slackware-security&y=2021&m=slackware-security.585069");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'dnsmasq' package(s) announced via the SSA:2021-040-01 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"New dnsmasq packages are available for Slackware 14.0, 14.1, 14.2, and -current
to fix security issues.


Here are the details from the Slackware 14.2 ChangeLog:
+--------------------------+
patches/packages/dnsmasq-2.84-i586-1_slack14.2.txz: Upgraded.
 This update fixes bugs and remotely exploitable security issues:
 Use the values of --min-port and --max-port in outgoing
 TCP connections to upstream DNS servers.
 Fix a remote buffer overflow problem in the DNSSEC code. Any
 dnsmasq with DNSSEC compiled in and enabled is vulnerable to this,
 referenced by CVE-2020-25681, CVE-2020-25682, CVE-2020-25683
 CVE-2020-25687.
 Be sure to only accept UDP DNS query replies at the address
 from which the query was originated. This keeps as much entropy
 in the {query-ID, random-port} tuple as possible, to help defeat
 cache poisoning attacks. Refer: CVE-2020-25684.
 Use the SHA-256 hash function to verify that DNS answers
 received are for the questions originally asked. This replaces
 the slightly insecure SHA-1 (when compiled with DNSSEC) or
 the very insecure CRC32 (otherwise). Refer: CVE-2020-25685.
 Handle multiple identical near simultaneous DNS queries better.
 Previously, such queries would all be forwarded
 independently. This is, in theory, inefficient but in practise
 not a problem, _except_ that is means that an answer for any
 of the forwarded queries will be accepted and cached.
 An attacker can send a query multiple times, and for each repeat,
 another {port, ID} becomes capable of accepting the answer he is
 sending in the blind, to random IDs and ports. The chance of a
 successful attack is therefore multiplied by the number of repeats
 of the query. The new behaviour detects repeated queries and
 merely stores the clients sending repeats so that when the
 first query completes, the answer can be sent to all the
 clients who asked. Refer: CVE-2020-25686.
 For more information, see:
 [link moved to references]
 [link moved to references]
 [link moved to references]
 [link moved to references]
 [link moved to references]
 [link moved to references]
 [link moved to references]
 (* Security fix *)
+--------------------------+");

  script_tag(name:"affected", value:"'dnsmasq' package(s) on Slackware 14.0, Slackware 14.1, Slackware 14.2, Slackware current.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-slack.inc");


res = "";
report = "";

if(!isnull(res = isslkpkgvuln(pkg:"dnsmasq", ver:"2.84-i486-1_slack14.0", rls:"SLK14.0"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"dnsmasq", ver:"2.84-x86_64-1_slack14.0", rls:"SLK14.0"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"dnsmasq", ver:"2.84-i486-1_slack14.1", rls:"SLK14.1"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"dnsmasq", ver:"2.84-x86_64-1_slack14.1", rls:"SLK14.1"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"dnsmasq", ver:"2.84-i586-1_slack14.2", rls:"SLK14.2"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"dnsmasq", ver:"2.84-x86_64-1_slack14.2", rls:"SLK14.2"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}
exit(0);
