###############################################################################
# OpenVAS Vulnerability Test
# $Id: glsa-201309-24.nasl 12128 2018-10-26 13:35:25Z cfischer $
#
# Gentoo Linux security check
#
# Authors:
# Eero Volotinen <eero.volotinen@solinor.com>
#
# Copyright:
# Copyright (c) 2015 Eero Volotinen, http://solinor.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.121038");
  script_version("$Revision: 12128 $");
  script_tag(name:"creation_date", value:"2015-09-29 11:26:01 +0300 (Tue, 29 Sep 2015)");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 15:35:25 +0200 (Fri, 26 Oct 2018) $");
  script_name("Gentoo Security Advisory GLSA 201309-24");
  script_tag(name:"insight", value:"Multiple vulnerabilities have been discovered in Xen. Please review the CVE identifiers referenced below for details.");
  script_tag(name:"solution", value:"Update the affected packages to the latest available version.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://security.gentoo.org/glsa/201309-24");
  script_cve_id("CVE-2012-2497", "CVE-2012-6030", "CVE-2012-6031", "CVE-2012-6032", "CVE-2012-6033", "CVE-2012-6034", "CVE-2012-6035", "CVE-2012-6036", "CVE-2011-2901", "CVE-2011-3262", "CVE-2012-0217", "CVE-2012-0218", "CVE-2012-2934", "CVE-2012-3432", "CVE-2012-3433", "CVE-2012-3494", "CVE-2012-3495", "CVE-2012-3496", "CVE-2012-3497", "CVE-2012-3498", "CVE-2012-3515", "CVE-2012-4411", "CVE-2012-4535", "CVE-2012-4536", "CVE-2012-4537", "CVE-2012-4538", "CVE-2012-4539", "CVE-2012-5510", "CVE-2012-5511", "CVE-2012-5512", "CVE-2012-5513", "CVE-2012-5514", "CVE-2012-5515", "CVE-2012-5525", "CVE-2012-5634", "CVE-2012-6075", "CVE-2012-6333", "CVE-2013-0151", "CVE-2013-0152", "CVE-2013-0153", "CVE-2013-0154", "CVE-2013-0215", "CVE-2013-1432", "CVE-2013-1917", "CVE-2013-1918", "CVE-2013-1919", "CVE-2013-1920", "CVE-2013-1922", "CVE-2013-1952", "CVE-2013-1964", "CVE-2013-2076", "CVE-2013-2077", "CVE-2013-2078", "CVE-2013-2194", "CVE-2013-2195", "CVE-2013-2196", "CVE-2013-2211");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"summary", value:"Gentoo Linux Local Security Checks GLSA 201309-24");
  script_copyright("Eero Volotinen");
  script_family("Gentoo Local Security Checks");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-gentoo.inc");

res = "";
report = "";

if((res=ispkgvuln(pkg:"app-emulation/xen", unaffected: make_list("ge 4.2.2-r1"), vulnerable: make_list("lt 4.2.2-r1"))) != NULL) {

  report += res;
}
if((res=ispkgvuln(pkg:"app-emulation/xen-tools", unaffected: make_list("ge 4.2.2-r3"), vulnerable: make_list("lt 4.2.2-r3"))) != NULL) {

  report += res;
}
if((res=ispkgvuln(pkg:"app-emulation/xen-pvgrub", unaffected: make_list("ge 4.2.2-r1"), vulnerable: make_list("lt 4.2.2-r1"))) != NULL) {
  report += res;
}

if(report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
