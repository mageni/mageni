###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for openldap RHSA-2010:0543-01
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
tag_insight = "OpenLDAP is an open source suite of LDAP (Lightweight Directory Access
  Protocol) applications and development tools.

  An uninitialized pointer use flaw was discovered in the way the slapd
  daemon handled modify relative distinguished name (modrdn) requests. An
  authenticated user with privileges to perform modrdn operations could use
  this flaw to crash the slapd daemon via specially-crafted modrdn requests.
  (CVE-2010-0211)
  
  Red Hat would like to thank CERT-FI for responsibly reporting the
  CVE-2010-0211 flaw, who credit Ilkka Mattila and Tuomas Salomki for the
  discovery of the issue.
  
  A flaw was found in the way OpenLDAP handled NUL characters in the
  CommonName field of X.509 certificates. An attacker able to get a
  carefully-crafted certificate signed by a trusted Certificate Authority
  could trick applications using OpenLDAP libraries into accepting it by
  mistake, allowing the attacker to perform a man-in-the-middle attack.
  (CVE-2009-3767)
  
  Users of OpenLDAP should upgrade to these updated packages, which contain
  backported patches to resolve these issues. After installing this update,
  the OpenLDAP daemons will be restarted automatically.";

tag_affected = "openldap on Red Hat Enterprise Linux AS version 4,
  Red Hat Enterprise Linux ES version 4,
  Red Hat Enterprise Linux WS version 4";
tag_solution = "Please Install the Updated Packages.";


if(description)
{
  script_xref(name : "URL" , value : "https://www.redhat.com/archives/rhsa-announce/2010-July/msg00010.html");
  script_oid("1.3.6.1.4.1.25623.1.0.315100");
  script_version("$Revision: 8250 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-27 08:29:15 +0100 (Wed, 27 Dec 2017) $");
  script_tag(name:"creation_date", value:"2010-07-23 16:10:25 +0200 (Fri, 23 Jul 2010)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_xref(name: "RHSA", value: "2010:0543-01");
  script_cve_id("CVE-2009-3767", "CVE-2010-0211");
  script_name("RedHat Update for openldap RHSA-2010:0543-01");

  script_tag(name: "summary" , value: "Check for the Version of openldap");
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

if(release == "RHENT_4")
{

  if ((res = isrpmvuln(pkg:"compat-openldap", rpm:"compat-openldap~2.1.30~12.el4_8.3", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openldap", rpm:"openldap~2.2.13~12.el4_8.3", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openldap-clients", rpm:"openldap-clients~2.2.13~12.el4_8.3", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openldap-debuginfo", rpm:"openldap-debuginfo~2.2.13~12.el4_8.3", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openldap-devel", rpm:"openldap-devel~2.2.13~12.el4_8.3", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openldap-servers", rpm:"openldap-servers~2.2.13~12.el4_8.3", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openldap-servers-sql", rpm:"openldap-servers-sql~2.2.13~12.el4_8.3", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
