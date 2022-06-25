###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for httpd CESA-2010:0175 centos4 i386
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
tag_insight = "The Apache HTTP Server is a popular web server.

  A use-after-free flaw was discovered in the way the Apache HTTP Server
  handled request headers in subrequests. In configurations where subrequests
  are used, a multithreaded MPM (Multi-Processing Module) could possibly leak
  information from other requests in request replies. (CVE-2010-0434)
  
  This update also fixes the following bug:
  
  * a bug was found in the mod_dav module. If a PUT request for an existing
  file failed, that file would be unexpectedly deleted and a &quot;Could not get
  next bucket brigade&quot; error logged. With this update, failed PUT requests no
  longer cause mod_dav to delete files, which resolves this issue.
  (BZ#572932)
  
  As well, this update adds the following enhancement:
  
  * with the updated openssl packages from RHSA-2010:0163 installed, mod_ssl
  will refuse to renegotiate a TLS/SSL connection with an unpatched client
  that does not support RFC 5746. This update adds the
  &quot;SSLInsecureRenegotiation&quot; configuration directive. If this directive is
  enabled, mod_ssl will renegotiate insecurely with unpatched clients.
  (BZ#575805)
  
  Refer to the following Red Hat Knowledgebase article for more details about
  the changed mod_ssl behavior: http://kbase.redhat.com/faq/docs/DOC-20491
  
  All httpd users should upgrade to these updated packages, which contain
  backported patches to correct these issues and add this enhancement. After
  installing the updated packages, the httpd daemon must be restarted for the
  update to take effect.";

tag_affected = "httpd on CentOS 4";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "http://lists.centos.org/pipermail/centos-announce/2010-March/016613.html");
  script_oid("1.3.6.1.4.1.25623.1.0.314664");
  script_version("$Revision: 8440 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-17 08:58:46 +0100 (Wed, 17 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-03-31 14:20:46 +0200 (Wed, 31 Mar 2010)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-2010-0434");
  script_name("CentOS Update for httpd CESA-2010:0175 centos4 i386");

  script_tag(name: "summary" , value: "Check for the Version of httpd");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms");
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

if(release == "CentOS4")
{

  if ((res = isrpmvuln(pkg:"httpd", rpm:"httpd~2.0.52~41.ent.7.centos4", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"httpd-devel", rpm:"httpd-devel~2.0.52~41.ent.7.centos4", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"httpd-manual", rpm:"httpd-manual~2.0.52~41.ent.7.centos4", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"httpd-suexec", rpm:"httpd-suexec~2.0.52~41.ent.7.centos4", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mod_ssl", rpm:"mod_ssl~2.0.52~41.ent.7.centos4", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
