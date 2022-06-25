###############################################################################
# OpenVAS Vulnerability Test
# $Id: alas-2014-307.nasl 6769 2017-07-20 09:56:33Z teissa$
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
  script_oid("1.3.6.1.4.1.25623.1.0.120528");
  script_version("$Revision: 11703 $");
  script_tag(name:"creation_date", value:"2015-09-08 13:28:38 +0200 (Tue, 08 Sep 2015)");
  script_tag(name:"last_modification", value:"$Date: 2018-10-01 10:05:31 +0200 (Mon, 01 Oct 2018) $");
  script_name("Amazon Linux Local Check: ALAS-2014-307");
  script_tag(name:"insight", value:"A heap-based buffer overflow and a use-after-free flaw were found in the tiff2pdf tool. An attacker could use these flaws to create a specially crafted TIFF file that would cause tiff2pdf to crash or, possibly, execute arbitrary code. (CVE-2013-1960, CVE-2013-4232 )Multiple buffer overflow flaws were found in the gif2tiff tool. An attacker could use these flaws to create a specially crafted GIF file that could cause gif2tiff to crash or, possibly, execute arbitrary code. (CVE-2013-4231, CVE-2013-4243, CVE-2013-4244 )A flaw was found in the way libtiff handled OJPEG-encoded TIFF images. An attacker could use this flaw to create a specially crafted TIFF file that would cause an application using libtiff to crash. (CVE-2010-2596 )Multiple buffer overflow flaws were found in the tiff2pdf tool. An attacker could use these flaws to create a specially crafted TIFF file that would cause tiff2pdf to crash. (CVE-2013-1961 )");
  script_tag(name:"solution", value:"Run yum update libtiff to update your system.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://alas.aws.amazon.com/ALAS-2014-307.html");
  script_cve_id("CVE-2010-2596", "CVE-2013-4244", "CVE-2013-4232", "CVE-2013-1960", "CVE-2013-4231", "CVE-2013-1961", "CVE-2013-4243");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
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
if ((res = isrpmvuln(pkg:"libtiff", rpm:"libtiff~3.9.4~10.12.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"libtiff-static", rpm:"libtiff-static~3.9.4~10.12.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"libtiff-debuginfo", rpm:"libtiff-debuginfo~3.9.4~10.12.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"libtiff-devel", rpm:"libtiff-devel~3.9.4~10.12.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if (__pkg_match) exit(99);
  exit(0);
}
