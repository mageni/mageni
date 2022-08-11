# OpenVAS Vulnerability Test
# $Id: deb_130_1.nasl 6616 2017-07-07 12:10:49Z cfischer $
# Description: Auto-generated from advisory DSA 130-1
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2007 E-Soft Inc. http://www.securityspace.com
# Text descriptions are largerly excerpted from the referenced
# advisory, and are Copyright (c) the respective author(s)
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
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

include("revisions-lib.inc");
tag_insight = "Ethereal versions prior to 0.9.3 were vulnerable to an allocation error
in the ASN.1 parser. This can be triggered when analyzing traffic using
the SNMP, LDAP, COPS, or Kerberos protocols in ethereal. This
vulnerability was announced in the ethereal security advisory
enpa-sa-00003 and has been given the proposed CVE id of CVE-2002-0353.
This issue has been corrected in ethereal version 0.8.0-3potato for
Debian 2.2 (potato).

Additionally, a number of vulnerabilities were discussed in ethereal
security advisory enpa-sa-00004; the version of ethereal in Debian 2.2
(potato) is not vulnerable to the issues raised in this later advisory.
Users of the not-yet-released woody distribution should ensure that they
are running ethereal 0.9.4-1 or a later version.

We recommend you upgrade your ethereal package immediately.";
tag_summary = "The remote host is missing an update to ethereal
announced via advisory DSA 130-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20130-1";

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.303634");
 script_version("$Revision: 6616 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:10:49 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2008-01-17 22:24:46 +0100 (Thu, 17 Jan 2008)");
 script_bugtraq_id(4604);
 script_cve_id("CVE-2002-0353");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_name("Debian Security Advisory DSA 130-1 (ethereal)");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2005 E-Soft Inc. http://www.securityspace.com");
 script_family("Debian Local Security Checks");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages");
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "insight" , value : tag_insight);
 script_tag(name : "summary" , value : tag_summary);
 script_tag(name:"qod_type", value:"package");
 script_tag(name:"solution_type", value:"VendorFix");
 exit(0);
}

#
# The script code starts here
#

include("pkg-lib-deb.inc");

res = "";
report = "";
if ((res = isdpkgvuln(pkg:"ethereal", ver:"0.8.0-3potato", rls:"DEB2.2")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
