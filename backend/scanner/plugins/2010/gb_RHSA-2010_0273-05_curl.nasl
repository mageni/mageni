###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for curl RHSA-2010:0273-05
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
tag_insight = "cURL is a tool for getting files from FTP, HTTP, Gopher, Telnet, and DICT
  servers, using any of the supported protocols. cURL is designed to work
  without user interaction or any kind of interactivity.

  Wesley Miaw discovered that when deflate compression was used, libcurl
  could call the registered write callback function with data exceeding the
  documented limit. A malicious server could use this flaw to crash an
  application using libcurl or, potentially, execute arbitrary code. Note:
  This issue only affected applications using libcurl that rely on the
  documented data size limit, and that copy the data to the insufficiently
  sized buffer. (CVE-2010-0734)
  
  This update also fixes the following bugs:
  
  * when using curl to upload a file, if the connection was broken or reset
  by the server during the transfer, curl immediately started using 100% CPU
  and failed to acknowledge that the transfer had failed. With this update,
  curl displays an appropriate error message and exits when an upload fails
  mid-transfer due to a broken or reset connection. (BZ#479967)
  
  * libcurl experienced a segmentation fault when attempting to reuse a
  connection after performing GSS-negotiate authentication, which in turn
  caused the curl program to crash. This update fixes this bug so that reused
  connections are able to be successfully established even after
  GSS-negotiate authentication has been performed. (BZ#517199)
  
  As well, this update adds the following enhancements:
  
  * curl now supports loading Certificate Revocation Lists (CRLs) from a
  Privacy Enhanced Mail (PEM) file. When curl attempts to access sites that
  have had their certificate revoked in a CRL, curl refuses access to those
  sites. (BZ#532069)
  
  * the curl(1) manual page has been updated to clarify that the &quot;--socks4&quot;
  and &quot;--socks5&quot; options do not work with the IPv6, FTPS, or LDAP protocols.
  (BZ#473128)
  
  * the curl utility's program help, which is accessed by running &quot;curl -h&quot;,
  has been updated with descriptions for the &quot;--ftp-account&quot; and
  &quot;--ftp-alternative-to-user&quot; options. (BZ#517084)
  
  Users of curl should upgrade to these updated packages, which contain
  backported patches to correct these issues and add these enhancements. All
  running applications using libcurl must be restarted for the update to take
  effect.";

tag_affected = "curl on Red Hat Enterprise Linux (v. 5 server)";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "https://www.redhat.com/archives/rhsa-announce/2010-March/msg00036.html");
  script_oid("1.3.6.1.4.1.25623.1.0.313086");
  script_version("$Revision: 8246 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-26 08:29:20 +0100 (Tue, 26 Dec 2017) $");
  script_tag(name:"creation_date", value:"2010-04-06 08:56:44 +0200 (Tue, 06 Apr 2010)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_xref(name: "RHSA", value: "2010:0273-05");
  script_cve_id("CVE-2010-0734");
  script_name("RedHat Update for curl RHSA-2010:0273-05");

  script_tag(name: "summary" , value: "Check for the Version of curl");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms");
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

if(release == "RHENT_5")
{

  if ((res = isrpmvuln(pkg:"curl", rpm:"curl~7.15.5~9.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"curl-debuginfo", rpm:"curl-debuginfo~7.15.5~9.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"curl-devel", rpm:"curl-devel~7.15.5~9.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
