###############################################################################
# OpenVAS Vulnerability Test
# $Id: alas-2015-597.nasl 6575 2017-07-06 13:42:08Z cfischer$
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
  script_oid("1.3.6.1.4.1.25623.1.0.120217");
  script_version("$Revision: 11703 $");
  script_tag(name:"creation_date", value:"2015-09-25 11:17:59 +0300 (Fri, 25 Sep 2015)");
  script_tag(name:"last_modification", value:"$Date: 2018-10-01 10:05:31 +0200 (Mon, 01 Oct 2018) $");
  script_name("Amazon Linux Local Check: alas-2015-597");
  script_tag(name:"insight", value:"An integer overflow flaw was found in the way libXfont processed certain Glyph Bitmap Distribution Format (BDF) fonts. A malicious, local user could use this flaw to crash the X.Org server or, potentially, execute arbitrary code with the privileges of the X.Org server. (CVE-2015-1802 )An integer truncation flaw was discovered in the way libXfont processed certain Glyph Bitmap Distribution Format (BDF) fonts. A malicious, local user could use this flaw to crash the X.Org server or, potentially, execute arbitrary code with the privileges of the X.Org server. (CVE-2015-1804 )A NULL pointer dereference flaw was discovered in the way libXfont processed certain Glyph Bitmap Distribution Format (BDF) fonts. A malicious, local user could use this flaw to crash the X.Org server. (CVE-2015-1803 )");
  script_tag(name:"solution", value:"Run yum update libXfont to update your system.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://alas.aws.amazon.com/ALAS-2015-597.html");
  script_cve_id("CVE-2015-1804", "CVE-2015-1802", "CVE-2015-1803");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:C/I:C/A:C");
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
if ((res = isrpmvuln(pkg:"libXfont-debuginfo", rpm:"libXfont-debuginfo~1.4.5~5.12.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"libXfont-devel", rpm:"libXfont-devel~1.4.5~5.12.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"libXfont", rpm:"libXfont~1.4.5~5.12.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if (__pkg_match) exit(99);
  exit(0);
}
