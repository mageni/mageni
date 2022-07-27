###############################################################################
# OpenVAS Vulnerability Test
# $Id: glsa-201502-12.nasl 12128 2018-10-26 13:35:25Z cfischer $
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
  script_oid("1.3.6.1.4.1.25623.1.0.121351");
  script_version("$Revision: 12128 $");
  script_tag(name:"creation_date", value:"2015-09-29 11:28:32 +0300 (Tue, 29 Sep 2015)");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 15:35:25 +0200 (Fri, 26 Oct 2018) $");
  script_name("Gentoo Security Advisory GLSA 201502-12");
  script_tag(name:"insight", value:"Multiple vulnerabilities have been discovered in Oracles Java SE Development Kit and Runtime Environment. Please review the CVE identifiers referenced below for details.");
  script_tag(name:"solution", value:"Update the affected packages to the latest available version.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://security.gentoo.org/glsa/201502-12");
  script_cve_id("CVE-2014-0429", "CVE-2014-0432", "CVE-2014-0446", "CVE-2014-0448", "CVE-2014-0449", "CVE-2014-0451", "CVE-2014-0452", "CVE-2014-0453", "CVE-2014-0454", "CVE-2014-0455", "CVE-2014-0456", "CVE-2014-0457", "CVE-2014-0458", "CVE-2014-0459", "CVE-2014-0460", "CVE-2014-0461", "CVE-2014-0463", "CVE-2014-0464", "CVE-2014-2397", "CVE-2014-2398", "CVE-2014-2401", "CVE-2014-2402", "CVE-2014-2403", "CVE-2014-2409", "CVE-2014-2410", "CVE-2014-2412", "CVE-2014-2413", "CVE-2014-2414", "CVE-2014-2420", "CVE-2014-2421", "CVE-2014-2422", "CVE-2014-2423", "CVE-2014-2427", "CVE-2014-2428", "CVE-2014-2483", "CVE-2014-2490", "CVE-2014-4208", "CVE-2014-4209", "CVE-2014-4216", "CVE-2014-4218", "CVE-2014-4219", "CVE-2014-4220", "CVE-2014-4221", "CVE-2014-4223", "CVE-2014-4227", "CVE-2014-4244", "CVE-2014-4247", "CVE-2014-4252", "CVE-2014-4262", "CVE-2014-4263", "CVE-2014-4264", "CVE-2014-4265", "CVE-2014-4266", "CVE-2014-4268", "CVE-2014-4288", "CVE-2014-6456", "CVE-2014-6457", "CVE-2014-6458", "CVE-2014-6466", "CVE-2014-6468", "CVE-2014-6476", "CVE-2014-6485", "CVE-2014-6492", "CVE-2014-6493", "CVE-2014-6502", "CVE-2014-6503", "CVE-2014-6504", "CVE-2014-6506", "CVE-2014-6511", "CVE-2014-6512", "CVE-2014-6513", "CVE-2014-6515", "CVE-2014-6517", "CVE-2014-6519", "CVE-2014-6527", "CVE-2014-6531", "CVE-2014-6532", "CVE-2014-6558", "CVE-2014-6562");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"summary", value:"Gentoo Linux Local Security Checks GLSA 201502-12");
  script_copyright("Eero Volotinen");
  script_family("Gentoo Local Security Checks");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-gentoo.inc");

res = "";
report = "";

if((res=ispkgvuln(pkg:"dev-java/oracle-jre-bin", unaffected: make_list("ge 1.7.0.71"), vulnerable: make_list("lt 1.7.0.71"))) != NULL) {

  report += res;
}
if((res=ispkgvuln(pkg:"dev-java/oracle-jdk-bin", unaffected: make_list("ge 1.7.0.71"), vulnerable: make_list("lt 1.7.0.71"))) != NULL) {

  report += res;
}
if((res=ispkgvuln(pkg:"app-emulation/emul-linux-x86-java", unaffected: make_list("ge 1.7.0.71"), vulnerable: make_list("lt 1.7.0.71"))) != NULL) {
  report += res;
}

if(report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
