###############################################################################
# OpenVAS Vulnerability Test
# $Id: alas-2014-458.nasl 6724 2017-07-14 09:57:17Z teissa$
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
  script_oid("1.3.6.1.4.1.25623.1.0.120019");
  script_version("$Revision: 11703 $");
  script_tag(name:"creation_date", value:"2015-09-08 13:15:11 +0200 (Tue, 08 Sep 2015)");
  script_tag(name:"last_modification", value:"$Date: 2018-10-01 10:05:31 +0200 (Mon, 01 Oct 2018) $");
  script_name("Amazon Linux Local Check: ALAS-2014-458");
  script_tag(name:"insight", value:"It was found that RPM could encounter an integer overflow, leading to a stack-based overflow, while parsing a crafted CPIO header in the payload section of an RPM file. This could allow an attacker to modify signed RPM files in such a way that they would execute code chosen by the attacker during package installation.  (CVE-2014-8118 )It was found that RPM wrote file contents to the target installation directory under a temporary name, and verified its cryptographic signature only after the temporary file has been written completely. Under certain conditions, the system interprets the unverified temporary file contents and extracts commands from it. This could allow an attacker to modify signed RPM files in such a way that they would execute code chosen by the attacker during package installation.  Red Hat has published an excellent analysis of this issue.  (CVE-2013-6435 )");
  script_tag(name:"solution", value:"Run yum update rpm to update your system.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://alas.aws.amazon.com/ALAS-2014-458.html");
  script_cve_id("CVE-2014-8118", "CVE-2013-6435");
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
if ((res = isrpmvuln(pkg:"rpm", rpm:"rpm~4.11.2~2.58.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"rpm-sign", rpm:"rpm-sign~4.11.2~2.58.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"rpm-build-libs", rpm:"rpm-build-libs~4.11.2~2.58.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"rpm-devel", rpm:"rpm-devel~4.11.2~2.58.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"rpm-python", rpm:"rpm-python~4.11.2~2.58.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"rpm-debuginfo", rpm:"rpm-debuginfo~4.11.2~2.58.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"rpm-build", rpm:"rpm-build~4.11.2~2.58.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"rpm-cron", rpm:"rpm-cron~4.11.2~2.58.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"rpm-apidocs", rpm:"rpm-apidocs~4.11.2~2.58.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if (__pkg_match) exit(99);
  exit(0);
}
