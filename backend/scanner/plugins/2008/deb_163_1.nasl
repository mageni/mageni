# OpenVAS Vulnerability Test
# $Id: deb_163_1.nasl 6616 2017-07-07 12:10:49Z cfischer $
# Description: Auto-generated from advisory DSA 163-1
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
tag_insight = "Jason Molenda and Hiromitsu Takagi found ways to exploit cross site
scripting bugs in mhonarc, a mail to HTML converter.  When processing
maliciously crafted mails of type text/html, mhonarc, does not
deactivate all scripting parts properly.  This is fixed in upstream
version 2.5.3.

If you are worried about security, it is recommended that you disable
support of text/html messages in your mail archives.  There is no
guarantee that the mhtxthtml.pl library is robust enough to eliminate
all possible exploits that can occur with HTML data.

To exclude HTML data, you can use the MIMEEXCS resource.  For example:

<MIMEExcs>
text/html
text/x-html
</MIMEExcs>

The use of text/x-html is probably not used any more, but is good to
include it, just-in-case.

If you are concerend that this could block out the entire contents of
some messages, then you could do the following instead:

<MIMEFilters>
text/html; m2h_text_plain::filter; mhtxtplain.pl
text/x-html; m2h_text_plain::filter; mhtxtplain.pl
</MIMEFilters>

This treats the HTML as text/plain.

The above problems have been fixed in version 2.5.2-1.1 for the
current stable stable distribution (woody), in version 2.4.4-1.1 for
the old stable distribution (potato) and in version 2.5.11-1 for the
unstable distribution (sid).

We recommend that you upgrade your mhonarc packages.";
tag_summary = "The remote host is missing an update to mhonarc
announced via advisory DSA 163-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20163-1";

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.302757");
 script_version("$Revision: 6616 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:10:49 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2008-01-17 22:24:46 +0100 (Thu, 17 Jan 2008)");
 script_cve_id("CVE-2002-0738");
 script_bugtraq_id(4546);
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_name("Debian Security Advisory DSA 163-1 (mhonarc)");



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
if ((res = isdpkgvuln(pkg:"mhonarc", ver:"2.4.4-1.1", rls:"DEB2.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mhonarc", ver:"2.5.2-1.1", rls:"DEB3.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
