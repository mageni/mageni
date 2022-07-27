###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for krb5 RHSA-2010:0343-01
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
tag_insight = "Kerberos is a network authentication system which allows clients and
  servers to authenticate to each other using symmetric encryption and a
  trusted third party, the Key Distribution Center (KDC).

  A use-after-free flaw was discovered in the MIT Kerberos administration
  daemon, kadmind. A remote, authenticated attacker could use this flaw to
  crash the kadmind daemon. Administrative privileges are not required to
  trigger this flaw, as any realm user can request information about their
  own principal from kadmind. (CVE-2010-0629)
  
  This update also fixes the following bug:
  
  * when a Kerberos client seeks tickets for use with a service, it must
  contact the Key Distribution Center (KDC) to obtain them. The client must
  also determine which realm the service belongs to and it typically does
  this with a combination of client configuration detail, DNS information and
  guesswork.
  
  If the service belongs to a realm other than the client's, cross-realm
  authentication is required. Using a combination of client configuration and
  guesswork, the client determines the trust relationship sequence which
  forms the trusted path between the client's realm and the service's realm.
  This may include one or more intermediate realms.
  
  Anticipating the KDC has better knowledge of extant trust relationships,
  the client then requests a ticket from the service's KDC, indicating it
  will accept guidance from the service's KDC by setting a special flag in
  the request. A KDC which recognizes the flag can, at its option, return a
  ticket-granting ticket for the next realm along the trust path the client
  should be following.
  
  If the ticket-granting ticket returned by the service's KDC is for use with
  a realm the client has already determined was in the trusted path, the
  client accepts this as an optimization and continues. If, however, the
  ticket is for use in a realm the client is not expecting, the client
  responds incorrectly: it treats the case as an error rather than continuing
  along the path suggested by the service's KDC.
  
  For this update, the krb5 1.7 modifications which allow the client to trust
  such KDCs to send them along the correct path, resulting in the client
  obtaining the tickets it originally desired, were backported to krb 1.6.1
  (the version shipped with Red Hat Enterprise Linux 5.5). (BZ#578540)
  
  All krb5 users should upgrade to these updated packages, which contain
  backported patches to correct these issues. All running KDC services must
  be restarted for the update to take effect.";

tag_affected = "krb5 on Red Hat Enterprise Linux (v. 5 server)";
tag_solution = "Please Install the Updated Packages.";


if(description)
{
  script_xref(name : "URL" , value : "https://www.redhat.com/archives/rhsa-announce/2010-April/msg00004.html");
  script_oid("1.3.6.1.4.1.25623.1.0.314687");
  script_version("$Revision: 8510 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-24 08:57:42 +0100 (Wed, 24 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-04-09 11:11:25 +0200 (Fri, 09 Apr 2010)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_xref(name: "RHSA", value: "2010:0343-01");
  script_cve_id("CVE-2010-0629");
  script_name("RedHat Update for krb5 RHSA-2010:0343-01");

  script_tag(name: "summary" , value: "Check for the Version of krb5");
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

  if ((res = isrpmvuln(pkg:"krb5-debuginfo", rpm:"krb5-debuginfo~1.6.1~36.el5_5.2", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"krb5-devel", rpm:"krb5-devel~1.6.1~36.el5_5.2", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"krb5-libs", rpm:"krb5-libs~1.6.1~36.el5_5.2", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"krb5-server", rpm:"krb5-server~1.6.1~36.el5_5.2", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"krb5-workstation", rpm:"krb5-workstation~1.6.1~36.el5_5.2", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
