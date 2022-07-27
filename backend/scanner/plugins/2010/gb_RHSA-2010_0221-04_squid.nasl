###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for squid RHSA-2010:0221-04
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
tag_insight = "Squid is a high-performance proxy caching server for web clients,
  supporting FTP, Gopher, and HTTP data objects.

  A flaw was found in the way Squid processed certain external ACL helper
  HTTP header fields that contained a delimiter that was not a comma. A
  remote attacker could issue a crafted request to the Squid server, causing
  excessive CPU use (up to 100%). (CVE-2009-2855)
  
  Note: The CVE-2009-2855 issue only affected non-default configurations that
  use an external ACL helper script.
  
  A flaw was found in the way Squid handled truncated DNS replies. A remote
  attacker able to send specially-crafted UDP packets to Squid's DNS client
  port could trigger an assertion failure in Squid's child process, causing
  that child process to exit. (CVE-2010-0308)
  
  This update also fixes the following bugs:
  
  * Squid's init script returns a non-zero value when trying to stop a
  stopped service. This is not LSB compliant and can generate difficulties in
  cluster environments. This update makes stopping LSB compliant. (BZ#521926)
  
  * Squid is not currently built to support MAC address filtering in ACLs.
  This update includes support for MAC address filtering. (BZ#496170)
  
  * Squid is not currently built to support Kerberos negotiate
  authentication. This update enables Kerberos authentication. (BZ#516245)
  
  * Squid does not include the port number as part of URIs it constructs when
  configured as an accelerator. This results in a 403 error. This update
  corrects this behavior. (BZ#538738)
  
  * the error_map feature does not work if the same handling is set also on
  the HTTP server that operates in deflate mode. This update fixes this
  issue. (BZ#470843)
  
  All users of squid should upgrade to this updated package, which resolves
  these issues. After installing this update, the squid service will be
  restarted automatically.";

tag_affected = "squid on Red Hat Enterprise Linux (v. 5 server)";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "https://www.redhat.com/archives/rhsa-announce/2010-March/msg00032.html");
  script_oid("1.3.6.1.4.1.25623.1.0.313987");
  script_version("$Revision: 8528 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-25 08:57:36 +0100 (Thu, 25 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-04-06 08:56:44 +0200 (Tue, 06 Apr 2010)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_xref(name: "RHSA", value: "2010:0221-04");
  script_cve_id("CVE-2009-2855", "CVE-2010-0308");
  script_name("RedHat Update for squid RHSA-2010:0221-04");

  script_tag(name: "summary" , value: "Check for the Version of squid");
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

  if ((res = isrpmvuln(pkg:"squid", rpm:"squid~2.6.STABLE21~6.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"squid-debuginfo", rpm:"squid-debuginfo~2.6.STABLE21~6.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
