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
  script_oid("1.3.6.1.4.1.25623.1.1.13.2005.251.03");
  script_cve_id("CVE-2004-0969", "CVE-2005-2102", "CVE-2005-2103", "CVE-2005-2370", "CVE-2005-2491", "CVE-2005-2494", "CVE-2005-2498", "CVE-2005-2700");
  script_tag(name:"creation_date", value:"2022-04-21 12:12:27 +0000 (Thu, 21 Apr 2022)");
  script_version("2022-05-09T10:02:45+0000");
  script_tag(name:"last_modification", value:"2022-05-09 10:02:45 +0000 (Mon, 09 May 2022)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Slackware: Security Advisory (SSA:2005-251-03)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Slackware Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/slackware_linux", "ssh/login/slackpack", re:"ssh/login/release=SLKcurrent");

  script_xref(name:"Advisory-ID", value:"SSA:2005-251-03");
  script_xref(name:"URL", value:"http://www.slackware.com/security/viewer.php?l=slackware-security&y=2005&m=slackware-security.651553");
  script_xref(name:"URL", value:"http://www.kde.org/info/security/advisory-20050905-1.txt");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'slackware-current' package(s) announced via the SSA:2005-251-03 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This advisory summarizes recent security fixes in Slackware -current.

Usually security advisories are not issued on problems that exist only
within the test version of Slackware (slackware-current), but since it's
so close to being released as Slackware 10.2, and since there have been
several -cuurent-only issues recently, it has been decided that it would
be a good idea to release a summary of all of the security fixes in
Slackware -current for the last 2 weeks. Some of these are -current only,
and some affect other versions of Slackware (and advisories for these
have already been issued).


Here are the details from the Slackware -current ChangeLog:
+--------------------------+
ap/groff-1.19.1-i486-3.tgz: Fixed a /tmp bug in groffer. Groffer is a
 script to display formatted output on the console or X, and is not normally
 used in other scripts (for printers, etc) like most groff components are.
 The risk from this bug is probably quite low. The fix was pulled from the
 just-released groff-1.19.2. With Slackware 10.2 just around the corner it
 didn't seem prudent to upgrade to that -- the diff from 1.19.1 to 1.19.2
 is over a megabyte compressed.
 For more information, see:
 [link moved to references]
 (* Security fix *)

kde/kdebase-3.4.2-i486-2.tgz: Patched a bug in Konqueror's handling of
 characters such as '*', '[', and '?'.
 Generated new kdm config files.
 Added /opt/kde/man to $MANPATH.
 Patched a security bug in kcheckpass that could allow a local user to
 gain root privileges.
 For more information, see:
 [link moved to references]
 [link moved to references]
 (* Security fix *)

n/mod_ssl-2.8.24_1.3.33-i486-1.tgz: Upgraded to mod_ssl-2.8.24-1.3.33.
 From the CHANGES file:
 Fix a security issue (CAN-2005-2700) where 'SSLVerifyClient require' was
 not enforced in per-location context if 'SSLVerifyClient optional' was
 configured in the global virtual host configuration.
 For more information, see:
 [link moved to references]
 (* Security fix *)

n/openssh-4.2p1-i486-1.tgz: Upgraded to openssh-4.2p1.
 From the OpenSSH 4.2 release announcement:
 SECURITY: Fix a bug introduced in OpenSSH 4.0 that caused
 GatewayPorts to be incorrectly activated for dynamic ('-D') port
 forwardings when no listen address was explicitly specified.
 (* Security fix *)

kde/kdeedu-3.4.2-i486-2.tgz: Fixed a minor /tmp bug in kvoctrain.
 (* Security fix *)

n/php-4.4.0-i486-3.tgz: Relinked with the system PCRE library, as the builtin
 library has a buffer overflow that could be triggered by the processing of a
 specially crafted regular expression.
 For more information, see:
 [link moved to references]
 (* Security fix *)
 Upgraded PEAR::XMLRPC to version 1.4.0, which eliminates the use of the
 insecure eval() function.
 For ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'slackware-current' package(s) on Slackware current.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-slack.inc");


res = "";
report = "";

if(!isnull(res = isslkpkgvuln(pkg:"gaim", ver:"1.5.0-i486-1", rls:"SLKcurrent"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"groff", ver:"1.19.1-i486-3", rls:"SLKcurrent"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"kdebase", ver:"3.4.2-i486-2", rls:"SLKcurrent"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"kdeedu", ver:"3.4.2-i486-2", rls:"SLKcurrent"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"mod_ssl", ver:"2.8.24_1.3.33-i486-1", rls:"SLKcurrent"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"openssh", ver:"4.2p1-i486-1", rls:"SLKcurrent"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"php", ver:"4.4.0-i486-3", rls:"SLKcurrent"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"php", ver:"5.0.4-i486-3", rls:"SLKcurrent"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}
exit(0);
