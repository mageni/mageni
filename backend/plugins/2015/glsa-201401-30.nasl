###############################################################################
# OpenVAS Vulnerability Test
# $Id: glsa-201401-30.nasl 12128 2018-10-26 13:35:25Z cfischer $
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
  script_oid("1.3.6.1.4.1.25623.1.0.121127");
  script_version("$Revision: 12128 $");
  script_tag(name:"creation_date", value:"2015-09-29 11:26:40 +0300 (Tue, 29 Sep 2015)");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 15:35:25 +0200 (Fri, 26 Oct 2018) $");
  script_name("Gentoo Security Advisory GLSA 201401-30");
  script_tag(name:"insight", value:"Multiple vulnerabilities have been reported in the Oracle Java implementation. Please review the CVE identifiers referenced below for details.");
  script_tag(name:"solution", value:"Update the affected packages to the latest available version.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://security.gentoo.org/glsa/201401-30");
  script_cve_id("CVE-2011-3563", "CVE-2011-5035", "CVE-2012-0497", "CVE-2012-0498", "CVE-2012-0499", "CVE-2012-0500", "CVE-2012-0501", "CVE-2012-0502", "CVE-2012-0503", "CVE-2012-0504", "CVE-2012-0505", "CVE-2012-0506", "CVE-2012-0507", "CVE-2012-0547", "CVE-2012-1531", "CVE-2012-1532", "CVE-2012-1533", "CVE-2012-1541", "CVE-2012-1682", "CVE-2012-1711", "CVE-2012-1713", "CVE-2012-1716", "CVE-2012-1717", "CVE-2012-1718", "CVE-2012-1719", "CVE-2012-1721", "CVE-2012-1722", "CVE-2012-1723", "CVE-2012-1724", "CVE-2012-1725", "CVE-2012-1726", "CVE-2012-3136", "CVE-2012-3143", "CVE-2012-3159", "CVE-2012-3174", "CVE-2012-3213", "CVE-2012-3216", "CVE-2012-3342", "CVE-2012-4416", "CVE-2012-4681", "CVE-2012-5067", "CVE-2012-5068", "CVE-2012-5069", "CVE-2012-5070", "CVE-2012-5071", "CVE-2012-5072", "CVE-2012-5073", "CVE-2012-5074", "CVE-2012-5075", "CVE-2012-5076", "CVE-2012-5077", "CVE-2012-5079", "CVE-2012-5081", "CVE-2012-5083", "CVE-2012-5084", "CVE-2012-5085", "CVE-2012-5086", "CVE-2012-5087", "CVE-2012-5088", "CVE-2012-5089", "CVE-2013-0169", "CVE-2013-0351", "CVE-2013-0401", "CVE-2013-0402", "CVE-2013-0409", "CVE-2013-0419", "CVE-2013-0422", "CVE-2013-0423", "CVE-2013-0430", "CVE-2013-0437", "CVE-2013-0438", "CVE-2013-0445", "CVE-2013-0446", "CVE-2013-0448", "CVE-2013-0449", "CVE-2013-0809", "CVE-2013-1473", "CVE-2013-1479", "CVE-2013-1481", "CVE-2013-1484", "CVE-2013-1485", "CVE-2013-1486", "CVE-2013-1487", "CVE-2013-1488", "CVE-2013-1491", "CVE-2013-1493", "CVE-2013-1500", "CVE-2013-1518", "CVE-2013-1537", "CVE-2013-1540", "CVE-2013-1557", "CVE-2013-1558", "CVE-2013-1561", "CVE-2013-1563", "CVE-2013-1564", "CVE-2013-1569", "CVE-2013-1571", "CVE-2013-2383", "CVE-2013-2384", "CVE-2013-2394", "CVE-2013-2400", "CVE-2013-2407", "CVE-2013-2412", "CVE-2013-2414", "CVE-2013-2415", "CVE-2013-2416", "CVE-2013-2417", "CVE-2013-2418", "CVE-2013-2419", "CVE-2013-2420", "CVE-2013-2421", "CVE-2013-2422", "CVE-2013-2423", "CVE-2013-2424", "CVE-2013-2425", "CVE-2013-2426", "CVE-2013-2427", "CVE-2013-2428", "CVE-2013-2429", "CVE-2013-2430", "CVE-2013-2431", "CVE-2013-2432", "CVE-2013-2433", "CVE-2013-2434", "CVE-2013-2435", "CVE-2013-2436", "CVE-2013-2437", "CVE-2013-2438", "CVE-2013-2439", "CVE-2013-2440", "CVE-2013-2442", "CVE-2013-2443", "CVE-2013-2444", "CVE-2013-2445", "CVE-2013-2446", "CVE-2013-2447", "CVE-2013-2448", "CVE-2013-2449", "CVE-2013-2450", "CVE-2013-2451", "CVE-2013-2452", "CVE-2013-2453", "CVE-2013-2454", "CVE-2013-2455", "CVE-2013-2456", "CVE-2013-2457", "CVE-2013-2458", "CVE-2013-2459", "CVE-2013-2460", "CVE-2013-2461", "CVE-2013-2462", "CVE-2013-2463", "CVE-2013-2464", "CVE-2013-2465", "CVE-2013-2466", "CVE-2013-2467", "CVE-2013-2468", "CVE-2013-2469", "CVE-2013-2470", "CVE-2013-2471", "CVE-2013-2472", "CVE-2013-2473", "CVE-2013-3743", "CVE-2013-3744", "CVE-2013-3829", "CVE-2013-5772", "CVE-2013-5774", "CVE-2013-5775", "CVE-2013-5776", "CVE-2013-5777", "CVE-2013-5778", "CVE-2013-5780", "CVE-2013-5782", "CVE-2013-5783", "CVE-2013-5784", "CVE-2013-5787", "CVE-2013-5788", "CVE-2013-5789", "CVE-2013-5790", "CVE-2013-5797", "CVE-2013-5800", "CVE-2013-5801", "CVE-2013-5802", "CVE-2013-5803", "CVE-2013-5804", "CVE-2013-5805", "CVE-2013-5806", "CVE-2013-5809", "CVE-2013-5810", "CVE-2013-5812", "CVE-2013-5814", "CVE-2013-5817", "CVE-2013-5818", "CVE-2013-5819", "CVE-2013-5820", "CVE-2013-5823", "CVE-2013-5824", "CVE-2013-5825", "CVE-2013-5829", "CVE-2013-5830", "CVE-2013-5831", "CVE-2013-5832", "CVE-2013-5838", "CVE-2013-5840", "CVE-2013-5842", "CVE-2013-5843", "CVE-2013-5844", "CVE-2013-5846", "CVE-2013-5848", "CVE-2013-5849", "CVE-2013-5850", "CVE-2013-5851", "CVE-2013-5852", "CVE-2013-5854", "CVE-2013-5870", "CVE-2013-5878", "CVE-2013-5887", "CVE-2013-5888", "CVE-2013-5889", "CVE-2013-5893", "CVE-2013-5895", "CVE-2013-5896", "CVE-2013-5898", "CVE-2013-5899", "CVE-2013-5902", "CVE-2013-5904", "CVE-2013-5905", "CVE-2013-5906", "CVE-2013-5907", "CVE-2013-5910", "CVE-2014-0368", "CVE-2014-0373", "CVE-2014-0375", "CVE-2014-0376", "CVE-2014-0382", "CVE-2014-0385", "CVE-2014-0387", "CVE-2014-0403", "CVE-2014-0408", "CVE-2014-0410", "CVE-2014-0411", "CVE-2014-0415", "CVE-2014-0416", "CVE-2014-0417", "CVE-2014-0418", "CVE-2014-0422", "CVE-2014-0423", "CVE-2014-0424", "CVE-2014-0428");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"summary", value:"Gentoo Linux Local Security Checks GLSA 201401-30");
  script_copyright("Eero Volotinen");
  script_family("Gentoo Local Security Checks");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-gentoo.inc");

res = "";
report = "";

if((res=ispkgvuln(pkg:"dev-java/sun-jdk", unaffected: make_list(), vulnerable: make_list("lt 1.6.0.45"))) != NULL) {

  report += res;
}
if((res=ispkgvuln(pkg:"dev-java/oracle-jdk-bin", unaffected: make_list("ge 1.7.0.51"), vulnerable: make_list("lt 1.7.0.51"))) != NULL) {

  report += res;
}
if((res=ispkgvuln(pkg:"dev-java/sun-jre-bin", unaffected: make_list(), vulnerable: make_list("lt 1.6.0.45"))) != NULL) {

  report += res;
}
if((res=ispkgvuln(pkg:"dev-java/oracle-jre-bin", unaffected: make_list("ge 1.7.0.51"), vulnerable: make_list("lt 1.7.0.51"))) != NULL) {

  report += res;
}
if((res=ispkgvuln(pkg:"app-emulation/emul-linux-x86-java", unaffected: make_list("ge 1.7.0.51"), vulnerable: make_list("lt 1.7.0.51"))) != NULL) {
  report += res;
}

if(report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
