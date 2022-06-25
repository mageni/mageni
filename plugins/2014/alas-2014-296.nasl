###############################################################################
# OpenVAS Vulnerability Test
# $Id: alas-2014-296.nasl 6913 2017-08-14 05:35:04Z asteins$
#
# Amazon Linux security check
#
# Authors:
# Eero Volotinen <eero.volotinen@iki.fi>
#
# Copyright:
# Copyright (c) 2015 Eero Volotinen, http://ping-viini.org
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.120157");
  script_version("$Revision: 11703 $");
  script_tag(name:"creation_date", value:"2015-09-08 13:18:47 +0200 (Tue, 08 Sep 2015)");
  script_tag(name:"last_modification", value:"$Date: 2018-10-01 10:05:31 +0200 (Mon, 01 Oct 2018) $");
  script_name("Amazon Linux Local Check: ALAS-2014-296");
  script_tag(name:"insight", value:"Stack-based buffer overflow in the chkNum function in lib/cgraph/scan.l in Graphviz 2.34.0 allows remote attackers to have unspecified impact via vectors related to a badly formed number and a long digit list. Stack-based buffer overflow in the yyerror function in lib/cgraph/scan.l in Graphviz 2.34.0 allows remote attackers to have unspecified impact via a long line in a dot file. Graphviz was recently reported to be affected by a buffer overflow vulnerability, which seem to have introduced in the fix for CVE-2014-0978 .");
  script_tag(name:"solution", value:"Run yum update graphviz to update your system.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://alas.aws.amazon.com/ALAS-2014-296.html");
  script_cve_id("CVE-2014-1235", "CVE-2014-1236", "CVE-2014-0978");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/amazon_linux", "ssh/login/release");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"summary", value:"Amazon Linux Local Security Checks");
  script_copyright("Eero Volotinen");
  script_family("Amazon Linux Local Security Checks");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "AMAZON")
{
if ((res = isrpmvuln(pkg:"graphviz-lua", rpm:"graphviz-lua~2.30.1~12.39.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"graphviz-java", rpm:"graphviz-java~2.30.1~12.39.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"graphviz-python", rpm:"graphviz-python~2.30.1~12.39.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"graphviz-ruby", rpm:"graphviz-ruby~2.30.1~12.39.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"graphviz-guile", rpm:"graphviz-guile~2.30.1~12.39.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"graphviz-php54", rpm:"graphviz-php54~2.30.1~12.39.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"graphviz-tcl", rpm:"graphviz-tcl~2.30.1~12.39.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"graphviz-gd", rpm:"graphviz-gd~2.30.1~12.39.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"graphviz-doc", rpm:"graphviz-doc~2.30.1~12.39.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"graphviz-graphs", rpm:"graphviz-graphs~2.30.1~12.39.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"graphviz-devel", rpm:"graphviz-devel~2.30.1~12.39.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"graphviz", rpm:"graphviz~2.30.1~12.39.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"graphviz-debuginfo", rpm:"graphviz-debuginfo~2.30.1~12.39.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"graphviz-perl", rpm:"graphviz-perl~2.30.1~12.39.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"graphviz-R", rpm:"graphviz-R~2.30.1~12.39.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if (__pkg_match) exit(99);
  exit(0);
}
