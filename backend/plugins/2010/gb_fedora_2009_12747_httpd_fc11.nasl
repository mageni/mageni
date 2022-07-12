###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for httpd FEDORA-2009-12747
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

include("revisions-lib.inc");
tag_insight = "The Apache HTTP Server is a powerful, efficient, and extensible
  web server.

  This update contains the latest stable release of Apache httpd. Three security
  fixes are included, along with several minor bug fixes.    A flaw was found in
  the way the TLS/SSL (Transport Layer Security/Secure Sockets Layer) protocols
  handle session renegotiation. A man-in-the-middle attacker could use this flaw
  to prefix arbitrary plain text to a client's session (for example, an HTTPS
  connection to a website). This could force the server to process an attacker's
  request as if authenticated using the victim's credentials. This update
  partially mitigates this flaw for SSL sessions to HTTP servers using mod_ssl by
  rejecting client-requested renegotiation. (CVE-2009-3555)    Note: This update
  does not fully resolve the issue for HTTPS servers. An attack is still possible
  in configurations that require a server-initiated renegotiation    A NULL
  pointer dereference flaw was found in the Apache mod_proxy_ftp module. A
  malicious FTP server to which requests are being proxied could use this flaw to
  crash an httpd child process via a malformed reply to the EPSV or PASV commands,
  resulting in a limited denial of service. (CVE-2009-3094)    A second flaw was
  found in the Apache mod_proxy_ftp module. In a reverse proxy configuration, a
  remote attacker could use this flaw to bypass intended access restrictions by
  creating a carefully-crafted HTTP Authorization header, allowing the attacker to
  send arbitrary commands to the FTP server. (CVE-2009-3095)    See the upstream
  changes file for further information:
  http://www.apache.org/dist/httpd/CHANGES_2.2.14";

tag_affected = "httpd on Fedora 11";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "http://lists.fedoraproject.org/pipermail/package-announce/2010-February/035949.html");
  script_oid("1.3.6.1.4.1.25623.1.0.313956");
  script_version("$Revision: 8528 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-25 08:57:36 +0100 (Thu, 25 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-03-02 08:38:02 +0100 (Tue, 02 Mar 2010)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_xref(name: "FEDORA", value: "2009-12747");
  script_cve_id("CVE-2009-3555", "CVE-2009-3094", "CVE-2009-3095");
  script_name("Fedora Update for httpd FEDORA-2009-12747");

  script_tag(name: "summary" , value: "Check for the Version of httpd");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms");
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("pkg-lib-rpm.inc");

release = get_kb_item("ssh/login/release");


res = "";
if(release == NULL){
  exit(0);
}

if(release == "FC11")
{

  if ((res = isrpmvuln(pkg:"httpd", rpm:"httpd~2.2.14~1.fc11", rls:"FC11")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
