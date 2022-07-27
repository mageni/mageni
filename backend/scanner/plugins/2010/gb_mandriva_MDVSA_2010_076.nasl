###############################################################################
# OpenVAS Vulnerability Test
#
# Mandriva Update for openssl MDVSA-2010:076 (openssl)
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
tag_insight = "This update fixes several security issues in openssl:
  - The ssl3_get_record function in ssl/s3_pkt.c in OpenSSL 0.9.8f
  through 0.9.8m allows remote attackers to cause a denial of service
  (crash) via a malformed record in a TLS connection (CVE-2010-0740)
  - OpenSSL before 0.9.8m does not check for a NULL return value
  from bn_wexpand function calls which has unspecified impact and
  context-dependent attack vectors (CVE-2009-3245)
  - The kssl_keytab_is_available function in ssl/kssl.c in OpenSSL
  before 0.9.8n, when Kerberos is enabled but Kerberos configuration
  files cannot be opened, could allow remote attackers to cause a denial
  of service (NULL pointer dereference and daemon crash) (CVE-2010-0433)
  - Finally, this update provides support for secure renegotiation,
  preventing men-in-the-middle attacks (CVE-2009-3555).

  Packages for 2008.0 and 2009.0 are provided due to the Extended
  Maintenance Program for those products.";
tag_solution = "Please Install the Updated Packages.";

tag_affected = "openssl on Mandriva Linux 2008.0,
  Mandriva Linux 2008.0/X86_64,
  Mandriva Linux 2009.1,
  Mandriva Linux 2009.1/X86_64,
  Mandriva Linux 2010.0,
  Mandriva Linux 2010.0/X86_64,
  Mandriva Enterprise Server 5,
  Mandriva Enterprise Server 5/X86_64";


if(description)
{
  script_xref(name : "URL" , value : "http://lists.mandriva.com/security-announce/2010-04/msg00024.php");
  script_oid("1.3.6.1.4.1.25623.1.0.313373");
  script_version("$Revision: 8440 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-17 08:58:46 +0100 (Wed, 17 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-04-19 16:47:49 +0200 (Mon, 19 Apr 2010)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_xref(name: "MDVSA", value: "2010:076");
  script_cve_id("CVE-2010-0740", "CVE-2009-3245", "CVE-2010-0433", "CVE-2009-3555");
  script_name("Mandriva Update for openssl MDVSA-2010:076 (openssl)");

  script_tag(name: "summary" , value: "Check for the Version of openssl");
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

if(release == "MNDK_2008.0")
{

  if ((res = isrpmvuln(pkg:"libopenssl0.9.8", rpm:"libopenssl0.9.8~0.9.8e~8.6mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libopenssl0.9.8-devel", rpm:"libopenssl0.9.8-devel~0.9.8e~8.6mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libopenssl0.9.8-static-devel", rpm:"libopenssl0.9.8-static-devel~0.9.8e~8.6mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openssl", rpm:"openssl~0.9.8e~8.6mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64openssl0.9.8", rpm:"lib64openssl0.9.8~0.9.8e~8.6mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64openssl0.9.8-devel", rpm:"lib64openssl0.9.8-devel~0.9.8e~8.6mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64openssl0.9.8-static-devel", rpm:"lib64openssl0.9.8-static-devel~0.9.8e~8.6mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "MNDK_2010.0")
{

  if ((res = isrpmvuln(pkg:"libopenssl0.9.8", rpm:"libopenssl0.9.8~0.9.8k~5.2mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libopenssl0.9.8-devel", rpm:"libopenssl0.9.8-devel~0.9.8k~5.2mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libopenssl0.9.8-static-devel", rpm:"libopenssl0.9.8-static-devel~0.9.8k~5.2mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openssl", rpm:"openssl~0.9.8k~5.2mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64openssl0.9.8", rpm:"lib64openssl0.9.8~0.9.8k~5.2mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64openssl0.9.8-devel", rpm:"lib64openssl0.9.8-devel~0.9.8k~5.2mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64openssl0.9.8-static-devel", rpm:"lib64openssl0.9.8-static-devel~0.9.8k~5.2mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "MNDK_2009.1")
{

  if ((res = isrpmvuln(pkg:"libopenssl0.9.8", rpm:"libopenssl0.9.8~0.9.8k~1.5mdv2009.1", rls:"MNDK_2009.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libopenssl0.9.8-devel", rpm:"libopenssl0.9.8-devel~0.9.8k~1.5mdv2009.1", rls:"MNDK_2009.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libopenssl0.9.8-static-devel", rpm:"libopenssl0.9.8-static-devel~0.9.8k~1.5mdv2009.1", rls:"MNDK_2009.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openssl", rpm:"openssl~0.9.8k~1.5mdv2009.1", rls:"MNDK_2009.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64openssl0.9.8", rpm:"lib64openssl0.9.8~0.9.8k~1.5mdv2009.1", rls:"MNDK_2009.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64openssl0.9.8-devel", rpm:"lib64openssl0.9.8-devel~0.9.8k~1.5mdv2009.1", rls:"MNDK_2009.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64openssl0.9.8-static-devel", rpm:"lib64openssl0.9.8-static-devel~0.9.8k~1.5mdv2009.1", rls:"MNDK_2009.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "MNDK_mes5")
{

  if ((res = isrpmvuln(pkg:"libopenssl0.9.8", rpm:"libopenssl0.9.8~0.9.8h~3.7mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libopenssl0.9.8-devel", rpm:"libopenssl0.9.8-devel~0.9.8h~3.7mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libopenssl0.9.8-static-devel", rpm:"libopenssl0.9.8-static-devel~0.9.8h~3.7mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openssl", rpm:"openssl~0.9.8h~3.7mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openssl", rpm:"openssl~0.9.8h~3.7mdv2009.0", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64openssl0.9.8", rpm:"lib64openssl0.9.8~0.9.8h~3.7mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64openssl0.9.8-devel", rpm:"lib64openssl0.9.8-devel~0.9.8h~3.7mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64openssl0.9.8-static-devel", rpm:"lib64openssl0.9.8-static-devel~0.9.8h~3.7mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
