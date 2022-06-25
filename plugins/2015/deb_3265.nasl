# OpenVAS Vulnerability Test
# $Id: deb_3265.nasl 14278 2019-03-18 14:47:26Z cfischer $
# Auto-generated from advisory DSA 3265-1 using nvtgen 1.0
# Script version: 1.0
#
# Author:
# Greenbone Networks
#
# Copyright:
# Copyright (c) 2015 Greenbone Networks GmbH http://greenbone.net
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (c) the respective author(s)
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
#

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703265");
  script_version("$Revision: 14278 $");
  script_cve_id("CVE-2012-5657", "CVE-2012-6532", "CVE-2014-2681", "CVE-2014-2682",
                  "CVE-2014-2683", "CVE-2014-2684", "CVE-2014-2685", "CVE-2014-4914",
                  "CVE-2014-8088", "CVE-2014-8089", "CVE-2015-3154");
  script_name("Debian Security Advisory DSA 3265-1 (zendframework - security update)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:47:26 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2015-05-20 00:00:00 +0200 (Wed, 20 May 2015)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"http://www.debian.org/security/2015/dsa-3265.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2015 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");
  script_tag(name:"affected", value:"zendframework on Debian Linux");
  script_tag(name:"solution", value:"For the oldstable distribution (wheezy),
these problems have been fixed in version 1.11.13-1.1+deb7u1.

For the stable distribution (jessie), these problems have been fixed in
version 1.12.9+dfsg-2+deb8u1.

For the testing distribution (stretch), these problems will be fixed
in version 1.12.12+dfsg-1.

For the unstable distribution (sid), these problems have been fixed in
version 1.12.12+dfsg-1.

We recommend that you upgrade your zendframework packages.");
  script_tag(name:"summary", value:"Multiple vulnerabilities were
discovered in Zend Framework, a PHP framework. Except for CVE-2015-3154
, all these issues were already fixed
in the version initially shipped with Jessie.

CVE-2014-2681Lukas Reschke reported a lack of protection against XML External
Entity injection attacks in some functions. This fix extends the
incomplete one from CVE-2012-5657
.

CVE-2014-2682Lukas Reschke reported a failure to consider that the
libxml_disable_entity_loader setting is shared among threads in the
PHP-FPM case. This fix extends the incomplete one from
CVE-2012-5657
.

CVE-2014-2683Lukas Reschke reported a lack of protection against XML Entity
Expansion attacks in some functions. This fix extends the incomplete
one from CVE-2012-6532
.

CVE-2014-2684
Christian Mainka and Vladislav Mladenov from the Ruhr-University
Bochum reported an error in the consumer's verify method that lead
to acceptance of wrongly sourced tokens.

CVE-2014-2685
Christian Mainka and Vladislav Mladenov from the Ruhr-University
Bochum reported a specification violation in which signing of a
single parameter is incorrectly considered sufficient.

CVE-2014-4914
Cassiano Dal Pizzol discovered that the implementation of the ORDER
BY SQL statement in Zend_Db_Select contains a potential SQL
injection when the query string passed contains parentheses.

CVE-2014-8088
Yury Dyachenko at Positive Research Center identified potential XML
eXternal Entity injection vectors due to insecure usage of PHP's DOM
extension.

CVE-2014-8089
Jonas Sandstrm discovered an SQL injection vector when manually
quoting value for sqlsrv extension, using null byte.

CVE-2015-3154
Filippo Tessarotto and Maks3w reported potential CRLF injection
attacks in mail and HTTP headers.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"zendframework", ver:"1.11.13-1.1+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"zendframework-bin", ver:"1.11.13-1.1+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"zendframework-resources", ver:"1.11.13-1.1+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if (__pkg_match) {
  exit(99);
}