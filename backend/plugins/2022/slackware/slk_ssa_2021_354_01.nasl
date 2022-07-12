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
  script_oid("1.3.6.1.4.1.25623.1.1.13.2021.354.01");
  script_cve_id("CVE-2021-44224", "CVE-2021-44790");
  script_tag(name:"creation_date", value:"2022-04-21 12:12:27 +0000 (Thu, 21 Apr 2022)");
  script_version("2022-05-05T07:49:10+0000");
  script_tag(name:"last_modification", value:"2022-05-10 10:06:01 +0000 (Tue, 10 May 2022)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-12-22 18:43:00 +0000 (Wed, 22 Dec 2021)");

  script_name("Slackware: Security Advisory (SSA:2021-354-01)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Slackware Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/slackware_linux", "ssh/login/slackpack", re:"ssh/login/release=SLK(14\.0|14\.1|14\.2)");

  script_xref(name:"Advisory-ID", value:"SSA:2021-354-01");
  script_xref(name:"URL", value:"http://www.slackware.com/security/viewer.php?l=slackware-security&y=2021&m=slackware-security.507663");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'httpd' package(s) announced via the SSA:2021-354-01 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"New httpd packages are available for Slackware 14.0, 14.1, 14.2, and -current
to fix security issues.


Here are the details from the Slackware 14.2 ChangeLog:
+--------------------------+
patches/packages/httpd-2.4.52-i586-1_slack14.2.txz: Upgraded.
 SECURITY: CVE-2021-44790: Possible buffer overflow when parsing
 multipart content in mod_lua of Apache HTTP Server 2.4.51 and
 earlier (cve.mitre.org)
 A carefully crafted request body can cause a buffer overflow in
 the mod_lua multipart parser (r:parsebody() called from Lua
 scripts).
 The Apache httpd team is not aware of an exploit for the
 vulnerability though it might be possible to craft one.
 This issue affects Apache HTTP Server 2.4.51 and earlier.
 Credits: Chamal
 SECURITY: CVE-2021-44224: Possible NULL dereference or SSRF in
 forward proxy configurations in Apache HTTP Server 2.4.51 and
 earlier (cve.mitre.org)
 A crafted URI sent to httpd configured as a forward proxy
 (ProxyRequests on) can cause a crash (NULL pointer dereference)
 or, for configurations mixing forward and reverse proxy
 declarations, can allow for requests to be directed to a
 declared Unix Domain Socket endpoint (Server Side Request
 Forgery).
 This issue affects Apache HTTP Server 2.4.7 up to 2.4.51
 (included).
 Credits: ae 1/4*a-o(R)e 1/4
 TengMA(@Te3t123)
 For more information, see:
 [link moved to references]
 [link moved to references]
 (* Security fix *)
+--------------------------+");

  script_tag(name:"affected", value:"'httpd' package(s) on Slackware 14.0, Slackware 14.1, Slackware 14.2, Slackware current.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-slack.inc");


res = "";
report = "";

if(!isnull(res = isslkpkgvuln(pkg:"httpd", ver:"2.4.52-i486-1_slack14.0", rls:"SLK14.0"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"httpd", ver:"2.4.52-x86_64-1_slack14.0", rls:"SLK14.0"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"httpd", ver:"2.4.52-i486-1_slack14.1", rls:"SLK14.1"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"httpd", ver:"2.4.52-x86_64-1_slack14.1", rls:"SLK14.1"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"httpd", ver:"2.4.52-i586-1_slack14.2", rls:"SLK14.2"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"httpd", ver:"2.4.52-x86_64-1_slack14.2", rls:"SLK14.2"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}
exit(0);
