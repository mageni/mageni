###############################################################################
# OpenVAS Vulnerability Test
# $Id: alas-2015-615.nasl 6575 2017-07-06 13:42:08Z cfischer$
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
  script_oid("1.3.6.1.4.1.25623.1.0.120605");
  script_version("$Revision: 11703 $");
  script_tag(name:"creation_date", value:"2015-12-15 02:51:18 +0200 (Tue, 15 Dec 2015)");
  script_tag(name:"last_modification", value:"$Date: 2018-10-01 10:05:31 +0200 (Mon, 01 Oct 2018) $");
  script_name("Amazon Linux Local Check: alas-2015-615");
  script_tag(name:"insight", value:"It was discovered that the png_get_PLTE() and png_set_PLTE() functions of libpng did not correctly calculate the maximum palette sizes for bit depths of less than 8. In case an application tried to use these functions in combination with properly calculated palette sizes, this could lead to a buffer overflow or out-of-bounds reads. An attacker could exploit this to cause a crash or potentially execute arbitrary code by tricking an unsuspecting user into processing a specially crafted PNG image. However, the exact impact is dependent on the application using the library. (CVE-2015-7981 )An array-indexing error was discovered in the png_convert_to_rfc1123() function of libpng. An attacker could possibly use this flaw to cause an out-of-bounds read by tricking an unsuspecting user into processing a specially crafted PNG image. (CVE-2015-8472 )");
  script_tag(name:"solution", value:"Run yum update libpng to update your system.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://alas.aws.amazon.com/ALAS-2015-615.html");
  script_cve_id("CVE-2015-7981", "CVE-2015-8472");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
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
if ((res = isrpmvuln(pkg:"libpng-devel", rpm:"libpng-devel~1.2.49~2.14.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"libpng-debuginfo", rpm:"libpng-debuginfo~1.2.49~2.14.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"libpng-static", rpm:"libpng-static~1.2.49~2.14.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"libpng", rpm:"libpng~1.2.49~2.14.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if (__pkg_match) exit(99);
  exit(0);
}
