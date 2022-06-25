#
#VID e15f2356-9139-11de-8f42-001aa0166822
# OpenVAS Vulnerability Test
# $
# Description: Auto generated from VID e15f2356-9139-11de-8f42-001aa0166822
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2009 E-Soft Inc. http://www.securityspace.com
# Text descriptions are largely excerpted from the referenced
# advisories, and are Copyright (c) the respective author(s)
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
tag_insight = "The following package is affected: apache

CVE-2009-1891
The mod_deflate module in Apache httpd 2.2.11 and earlier compresses
large files until completion even after the associated network
connection is closed, which allows remote attackers to cause a denial
of service (CPU consumption).

CVE-2009-1195
The Apache HTTP Server 2.2.11 and earlier 2.2 versions does not
properly handle Options=IncludesNOEXEC in the AllowOverride directive,
which allows local users to gain privileges by configuring (1) Options
Includes, (2) Options +Includes, or (3) Options +IncludesNOEXEC in a
.htaccess file, and then inserting an exec element in a .shtml file.

CVE-2009-1890
The stream_reqbody_cl function in mod_proxy_http.c in the mod_proxy
module in the Apache HTTP Server before 2.3.3, when a reverse proxy is
configured, does not properly handle an amount of streamed data that
exceeds the Content-Length value, which allows remote attackers to
cause a denial of service (CPU consumption) via crafted requests.

CVE-2009-1191
mod_proxy_ajp.c in the mod_proxy_ajp module in the Apache HTTP Server
2.2.11 allows remote attackers to obtain sensitive response data,
intended for a client that sent an earlier POST request with no
request body, via an HTTP request.

CVE-2009-0023
The apr_strmatch_precompile function in strmatch/apr_strmatch.c in
Apache APR-util before 1.3.5 allows remote attackers to cause a denial
of service (daemon crash) via crafted input involving (1) a .htaccess
file used with the Apache HTTP Server, (2) the SVNMasterURI directive
in the mod_dav_svn module in the Apache HTTP Server, (3) the
mod_apreq2 module for the Apache HTTP Server, or (4) an application
that uses the libapreq2 library, which triggers a heap-based buffer
underflow.

CVE-2009-1955
The expat XML parser in the apr_xml_* interface in xml/apr_xml.c in
Apache APR-util before 1.3.7, as used in the mod_dav and mod_dav_svn
modules in the Apache HTTP Server, allows remote attackers to cause a
denial of service (memory consumption) via a crafted XML document
containing a large number of nested entity references, as demonstrated
by a PROPFIND request, a similar issue to CVE-2003-1564.

CVE-2009-1956
Off-by-one error in the apr_brigade_vprintf function in Apache
APR-util before 1.3.5 on big-endian platforms allows remote attackers
to obtain sensitive information or cause a denial of service
(application crash) via crafted input.";
tag_summary = "The remote host is missing an update to the system
as announced in the referenced advisory.";

tag_solution = "Update your system with the appropriate patches or
software upgrades.";



if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.305107");
 script_version("$Revision: 4824 $");
 script_tag(name:"last_modification", value:"$Date: 2016-12-21 09:49:38 +0100 (Wed, 21 Dec 2016) $");
 script_tag(name:"creation_date", value:"2009-09-02 04:58:39 +0200 (Wed, 02 Sep 2009)");
 script_cve_id("CVE-2009-1891", "CVE-2009-1195", "CVE-2009-1890", "CVE-2009-1191", "CVE-2009-0023", "CVE-2009-1955", "CVE-2009-1956");
 script_tag(name:"cvss_base", value:"7.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
 script_name("FreeBSD Ports: apache");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2009 E-Soft Inc. http://www.securityspace.com");
 script_family("FreeBSD Local Security Checks");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("ssh/login/freebsdrel", "login/SSH/success");
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

include("pkg-lib-bsd.inc");

txt = "";
vuln = 0;
bver = portver(pkg:"apache");
if(!isnull(bver) && revcomp(a:bver, b:"2.2.0")>0 && revcomp(a:bver, b:"2.2.12")<0) {
    txt += 'Package apache version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}

if(vuln) {
    security_message(data:string(txt));
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
