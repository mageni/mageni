###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for httpd RHSA-2010:0659-01
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

  A flaw was discovered in the way the mod_proxy module of the Apache HTTP
  Server handled the timeouts of requests forwarded by a reverse proxy to the
  back-end server. If the proxy was configured to reuse existing back-end
  connections, it could return a response intended for another user under
  certain timeout conditions, possibly leading to information disclosure.
  (CVE-2010-2791)

  A flaw was found in the way the mod_dav module of the Apache HTTP Server
  handled certain requests. If a remote attacker were to send a carefully
  crafted request to the server, it could cause the httpd child process to
  crash. (CVE-2010-1452)

  This update also fixes the following bugs:

  * numerous issues in the INFLATE filter provided by mod_deflate. &quot;Inflate
  error -5 on flush&quot; errors may have been logged. This update upgrades
  mod_deflate to the newer upstream version from Apache HTTP Server 2.2.15.
  (BZ#625435)

  * the response would be corrupted if mod_filter applied the DEFLATE filter
  to a resource requiring a subrequest with an internal redirect. (BZ#625451)

  * the OID() function used in the mod_ssl &quot;SSLRequire&quot; directive did not
  correctly evaluate extensions of an unknown type. (BZ#625452)

  All httpd users should upgrade to these updated packages, which contain
  backported patches to correct these issues. After installing the updated
  packages, the httpd daemon must be restarted for the update to take effect.";

tag_affected = "httpd on Red Hat Enterprise Linux (v. 5 server)";
tag_solution = "Please Install the Updated Packages.";


if(description)
{
  script_xref(name : "URL" , value : "https://www.redhat.com/archives/rhsa-announce/2010-August/msg00032.html");
  script_oid("1.3.6.1.4.1.25623.1.0.314259");
  script_version("$Revision: 8254 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-28 08:29:05 +0100 (Thu, 28 Dec 2017) $");
  script_tag(name:"creation_date", value:"2010-09-07 07:38:40 +0200 (Tue, 07 Sep 2010)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_xref(name: "RHSA", value: "2010:0659-01");
  script_cve_id("CVE-2010-1452", "CVE-2010-2791");
  script_name("RedHat Update for httpd RHSA-2010:0659-01");

  script_tag(name: "summary" , value: "Check for the Version of httpd");
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

  if ((res = isrpmvuln(pkg:"httpd", rpm:"httpd~2.2.3~43.el5_5.3", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"httpd-debuginfo", rpm:"httpd-debuginfo~2.2.3~43.el5_5.3", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"httpd-devel", rpm:"httpd-devel~2.2.3~43.el5_5.3", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"httpd-manual", rpm:"httpd-manual~2.2.3~43.el5_5.3", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mod_ssl", rpm:"mod_ssl~2.2.3~43.el5_5.3", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
