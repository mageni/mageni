###############################################################################
# OpenVAS Vulnerability Test
# $Id: glsa-201504-01.nasl 12128 2018-10-26 13:35:25Z cfischer $
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
  script_oid("1.3.6.1.4.1.25623.1.0.121368");
  script_version("$Revision: 12128 $");
  script_tag(name:"creation_date", value:"2015-09-29 11:28:42 +0300 (Tue, 29 Sep 2015)");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 15:35:25 +0200 (Fri, 26 Oct 2018) $");
  script_name("Gentoo Security Advisory GLSA 201504-01");
  script_tag(name:"insight", value:"Multiple vulnerabilities have been discovered in Firefox, Thunderbird, and SeaMonkey. Please review the CVE identifiers referenced below for details.");
  script_tag(name:"solution", value:"Update the affected packages to the latest available version.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://security.gentoo.org/glsa/201504-01");
  script_cve_id("CVE-2013-1741", "CVE-2013-2566", "CVE-2013-5590", "CVE-2013-5591", "CVE-2013-5592", "CVE-2013-5593", "CVE-2013-5595", "CVE-2013-5596", "CVE-2013-5597", "CVE-2013-5598", "CVE-2013-5599", "CVE-2013-5600", "CVE-2013-5601", "CVE-2013-5602", "CVE-2013-5603", "CVE-2013-5604", "CVE-2013-5605", "CVE-2013-5606", "CVE-2013-5607", "CVE-2013-5609", "CVE-2013-5610", "CVE-2013-5612", "CVE-2013-5613", "CVE-2013-5614", "CVE-2013-5615", "CVE-2013-5616", "CVE-2013-5618", "CVE-2013-5619", "CVE-2013-6671", "CVE-2013-6672", "CVE-2013-6673", "CVE-2014-1477", "CVE-2014-1478", "CVE-2014-1479", "CVE-2014-1480", "CVE-2014-1481", "CVE-2014-1482", "CVE-2014-1483", "CVE-2014-1485", "CVE-2014-1486", "CVE-2014-1487", "CVE-2014-1488", "CVE-2014-1489", "CVE-2014-1490", "CVE-2014-1491", "CVE-2014-1492", "CVE-2014-1493", "CVE-2014-1494", "CVE-2014-1496", "CVE-2014-1497", "CVE-2014-1498", "CVE-2014-1499", "CVE-2014-1500", "CVE-2014-1502", "CVE-2014-1504", "CVE-2014-1505", "CVE-2014-1508", "CVE-2014-1509", "CVE-2014-1510", "CVE-2014-1511", "CVE-2014-1512", "CVE-2014-1513", "CVE-2014-1514", "CVE-2014-1518", "CVE-2014-1519", "CVE-2014-1520", "CVE-2014-1522", "CVE-2014-1523", "CVE-2014-1524", "CVE-2014-1525", "CVE-2014-1526", "CVE-2014-1529", "CVE-2014-1530", "CVE-2014-1531", "CVE-2014-1532", "CVE-2014-1533", "CVE-2014-1534", "CVE-2014-1536", "CVE-2014-1537", "CVE-2014-1538", "CVE-2014-1539", "CVE-2014-1540", "CVE-2014-1541", "CVE-2014-1542", "CVE-2014-1543", "CVE-2014-1544", "CVE-2014-1545", "CVE-2014-1547", "CVE-2014-1548", "CVE-2014-1549", "CVE-2014-1550", "CVE-2014-1551", "CVE-2014-1552", "CVE-2014-1553", "CVE-2014-1554", "CVE-2014-1555", "CVE-2014-1556", "CVE-2014-1557", "CVE-2014-1558", "CVE-2014-1559", "CVE-2014-1560", "CVE-2014-1561", "CVE-2014-1562", "CVE-2014-1563", "CVE-2014-1564", "CVE-2014-1565", "CVE-2014-1566", "CVE-2014-1567", "CVE-2014-1568", "CVE-2014-1574", "CVE-2014-1575", "CVE-2014-1576", "CVE-2014-1577", "CVE-2014-1578", "CVE-2014-1580", "CVE-2014-1581", "CVE-2014-1582", "CVE-2014-1583", "CVE-2014-1584", "CVE-2014-1585", "CVE-2014-1586", "CVE-2014-1587", "CVE-2014-1588", "CVE-2014-1589", "CVE-2014-1590", "CVE-2014-1591", "CVE-2014-1592", "CVE-2014-1593", "CVE-2014-1594", "CVE-2014-5369", "CVE-2014-8631", "CVE-2014-8632", "CVE-2014-8634", "CVE-2014-8635", "CVE-2014-8636", "CVE-2014-8637", "CVE-2014-8638", "CVE-2014-8639", "CVE-2014-8640", "CVE-2014-8641", "CVE-2014-8642", "CVE-2015-0817", "CVE-2015-0818", "CVE-2015-0819", "CVE-2015-0820", "CVE-2015-0821", "CVE-2015-0822", "CVE-2015-0823", "CVE-2015-0824", "CVE-2015-0825", "CVE-2015-0826", "CVE-2015-0827", "CVE-2015-0828", "CVE-2015-0829", "CVE-2015-0830", "CVE-2015-0831", "CVE-2015-0832", "CVE-2015-0833", "CVE-2015-0834", "CVE-2015-0835", "CVE-2015-0836");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"summary", value:"Gentoo Linux Local Security Checks GLSA 201504-01");
  script_copyright("Eero Volotinen");
  script_family("Gentoo Local Security Checks");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-gentoo.inc");

res = "";
report = "";

if((res=ispkgvuln(pkg:"www-client/firefox", unaffected: make_list("ge 31.5.3"), vulnerable: make_list("lt 31.5.3"))) != NULL) {

  report += res;
}
if((res=ispkgvuln(pkg:"www-client/firefox-bin", unaffected: make_list("ge 31.5.3"), vulnerable: make_list("lt 31.5.3"))) != NULL) {

  report += res;
}
if((res=ispkgvuln(pkg:"mail-client/thunderbird", unaffected: make_list("ge 31.5.0"), vulnerable: make_list("lt 31.5.0"))) != NULL) {

  report += res;
}
if((res=ispkgvuln(pkg:"mail-client/thunderbird-bin", unaffected: make_list("ge 31.5.0"), vulnerable: make_list("lt 31.5.0"))) != NULL) {

  report += res;
}
if((res=ispkgvuln(pkg:"www-client/seamonkey", unaffected: make_list("ge 2.33.1"), vulnerable: make_list("lt 2.33.1"))) != NULL) {

  report += res;
}
if((res=ispkgvuln(pkg:"www-client/seamonkey-bin", unaffected: make_list("ge 2.33.1"), vulnerable: make_list("lt 2.33.1"))) != NULL) {

  report += res;
}
if((res=ispkgvuln(pkg:"dev-libs/nspr", unaffected: make_list("ge 4.10.6"), vulnerable: make_list("lt 4.10.6"))) != NULL) {
  report += res;
}

if(report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
