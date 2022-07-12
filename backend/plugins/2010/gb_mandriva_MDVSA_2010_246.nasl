###############################################################################
# OpenVAS Vulnerability Test
#
# Mandriva Update for krb5 MDVSA-2010:246 (krb5)
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
tag_insight = "Multiple vulnerabilities were discovered and corrected in krb5:

  An unauthenticated remote attacker could alter a SAM-2 challenge,
  affecting the prompt text seen by the user or the kind of response
  sent to the KDC. Under some circumstances, this can negate the
  incremental security benefit of using a single-use authentication
  mechanism token. An unauthenticated remote attacker has a 1/256
  chance of forging KRB-SAFE messages in an application protocol if the
  targeted pre-existing session uses an RC4 session key.  Few application
  protocols use KRB-SAFE messages (CVE-2010-1323).
  
  An unauthenticated remote attacker can forge GSS tokens that
  are intended to be integrity-protected but unencrypted, if the
  targeted pre-existing application session uses a DES session key. An
  authenticated remote attacker can forge PACs if using a KDC that does
  not filter client-provided PAC data.  This can result in privilege
  escalation against a service that relies on PAC contents to make
  authorization decisions. An unauthenticated remote attacker has a 1/256
  chance of swapping a client-issued KrbFastReq into a different KDC-REQ,
  if the armor key is RC4.  The consequences are believed to be minor
  (CVE-2010-1324).
  
  An authenticated remote attacker that controls a legitimate service
  principal has a 1/256 chance of forging the AD-SIGNEDPATH signature
  if the TGT key is RC4, allowing it to use self-generated evidence
  tickets for S4U2Proxy, instead of tickets obtained from the user or
  with S4U2Self.  Configurations using RC4 for the TGT key are believed
  to be rare. An authenticated remote attacker has a 1/256 chance of
  forging AD-KDC-ISSUED signatures on authdata elements in tickets
  having an RC4 service key, resulting in privilege escalation against
  a service that relies on these signatures.  There are no known uses
  of the KDC-ISSUED authdata container at this time (CVE-2010-4020.
  
  An authenticated remote attacker that controls a legitimate service
  principal could obtain a valid service ticket to itself containing
  valid KDC-generated authorization data for a client whose TGS-REQ
  it has intercepted.  The attacker could then use this ticket for
  S4U2Proxy to impersonate the targeted client even if the client never
  authenticated to the subverted service.  The vulnerable configuration
  is believed to be rare (CVE-2010-4021).
  
  The updated packages have been patched to correct this issue.";
tag_solution = "Please Install the Updated Packages.";

tag_affected = "krb5 on Mandriva Linux 2010.1,
  Mandriva Linux 2010.1/X86_64,
  Mandriva Enterprise Server 5,
  Mandriva Enterprise Server 5/X86_64";


if(description)
{
  script_xref(name : "URL" , value : "http://lists.mandriva.com/security-announce/2010-12/msg00001.php");
  script_oid("1.3.6.1.4.1.25623.1.0.313105");
  script_version("$Revision: 8250 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-27 08:29:15 +0100 (Wed, 27 Dec 2017) $");
  script_tag(name:"creation_date", value:"2010-12-09 08:26:35 +0100 (Thu, 09 Dec 2010)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_xref(name: "MDVSA", value: "2010:246");
  script_cve_id("CVE-2010-1323", "CVE-2010-1324", "CVE-2010-4020", "CVE-2010-4021");
  script_name("Mandriva Update for krb5 MDVSA-2010:246 (krb5)");

  script_tag(name: "summary" , value: "Check for the Version of krb5");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("Mandrake Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mandriva_mandrake_linux", "ssh/login/release");
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
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

if(release == "MNDK_mes5")
{

  if ((res = isrpmvuln(pkg:"krb5", rpm:"krb5~1.8.1~0.3mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"krb5-pkinit-openssl", rpm:"krb5-pkinit-openssl~1.8.1~0.3mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"krb5-server", rpm:"krb5-server~1.8.1~0.3mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"krb5-server-ldap", rpm:"krb5-server-ldap~1.8.1~0.3mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"krb5-workstation", rpm:"krb5-workstation~1.8.1~0.3mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libkrb53", rpm:"libkrb53~1.8.1~0.3mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libkrb53-devel", rpm:"libkrb53-devel~1.8.1~0.3mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64krb53", rpm:"lib64krb53~1.8.1~0.3mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64krb53-devel", rpm:"lib64krb53-devel~1.8.1~0.3mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "MNDK_2010.1")
{

  if ((res = isrpmvuln(pkg:"krb5", rpm:"krb5~1.8.1~5.2mdv2010.1", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"krb5-pkinit-openssl", rpm:"krb5-pkinit-openssl~1.8.1~5.2mdv2010.1", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"krb5-server", rpm:"krb5-server~1.8.1~5.2mdv2010.1", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"krb5-server-ldap", rpm:"krb5-server-ldap~1.8.1~5.2mdv2010.1", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"krb5-workstation", rpm:"krb5-workstation~1.8.1~5.2mdv2010.1", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libkrb53", rpm:"libkrb53~1.8.1~5.2mdv2010.1", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libkrb53-devel", rpm:"libkrb53-devel~1.8.1~5.2mdv2010.1", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64krb53", rpm:"lib64krb53~1.8.1~5.2mdv2010.1", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64krb53-devel", rpm:"lib64krb53-devel~1.8.1~5.2mdv2010.1", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
