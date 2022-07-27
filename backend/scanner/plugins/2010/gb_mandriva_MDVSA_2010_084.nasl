###############################################################################
# OpenVAS Vulnerability Test
#
# Mandriva Update for java-1.6.0-openjdk MDVSA-2010:084 (java-1.6.0-openjdk)
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
tag_insight = "Multiple Java OpenJDK security vulnerabilities has been identified
  and fixed:

  - TLS: MITM attacks via session renegotiation (CVE-2009-3555).
  - Loader-constraint table allows arrays instead of only the b
  ase-classes (CVE-2010-0082).
  - Policy/PolicyFile leak dynamic ProtectionDomains. (CVE-2010-0084).
  - File TOCTOU deserialization vulnerability (CVE-2010-0085).
  - Inflater/Deflater clone issues (CVE-2010-0088).
  - Unsigned applet can retrieve the dragged information before drop
  action occurs (CVE-2010-0091).
  - AtomicReferenceArray causes SIGSEGV -&gt; SEGV_MAPERR error
  (CVE-2010-0092).
  - System.arraycopy unable to reference elements beyond
  Integer.MAX_VALUE bytes (CVE-2010-0093).
  - Deserialization of RMIConnectionImpl objects should enforce stricter
  checks (CVE-2010-0094).
  - Subclasses of InetAddress may incorrectly interpret network addresses
  (CVE-2010-0095).
  - JAR unpack200 must verify input parameters (CVE-2010-0837).
  - CMM readMabCurveData Buffer Overflow Vulnerability (CVE-2010-0838).
  - Applet Trusted Methods Chaining Privilege Escalation Vulner ability
  (CVE-2010-0840).
  - No ClassCastException for HashAttributeSet constructors if run with
  -Xcomp (CVE-2010-0845)
  - ImagingLib arbitrary code execution vulnerability (CVE-2010-0847).
  - AWT Library Invalid Index Vulnerability (CVE-2010-0848).
  
  Additional security issues that was fixed with IcedTea6 1.6.2:
  - deprecate MD2 in SSL cert validation (CVE-2009-2409).
  - ICC_Profile file existence detection information leak
  (CVE-2009-3728).
  - JRE AWT setDifflCM stack overflow (CVE-2009-3869).
  - JRE AWT setBytePixels heap overflow (CVE-2009-3871).
  - JPEG Image Writer quantization problem (CVE-2009-3873).
  - ImageI/O JPEG heap overflow (CVE-2009-3874).
  - MessageDigest.isEqual introduces timing attack vulnerabilities
  (CVE-2009-3875).
  - OpenJDK ASN.1/DER input stream parser denial of service
  (CVE-2009-3876, CVE-2009-3877)
  - GraphicsConfiguration information leak (CVE-2009-3879).
  - UI logging information leakage (CVE-2009-3880).
  - resurrected classloaders can still have children (CVE-2009-3881).
  - Numerous static security flaws in Swing (findbugs) (CVE-2009-3882).
  - Mutable statics in Windows PL&amp;F (findbugs) (CVE-2009-3883).
  - zoneinfo file existence information leak (CVE-2009-3884).
  - BMP parsing DoS with UNC ICC links (CVE-2009-3885 ... 

  Description truncated, for more information please check the Reference URL";
tag_solution = "Please Install the Updated Packages.";

tag_affected = "java-1.6.0-openjdk on Mandriva Linux 2009.0,
  Mandriva Linux 2009.0/X86_64,
  Mandriva Linux 2009.1,
  Mandriva Linux 2009.1/X86_64,
  Mandriva Linux 2010.0,
  Mandriva Linux 2010.0/X86_64,
  Mandriva Enterprise Server 5,
  Mandriva Enterprise Server 5/X86_64";


if(description)
{
  script_xref(name : "URL" , value : "http://lists.mandriva.com/security-announce/2010-04/msg00048.php");
  script_oid("1.3.6.1.4.1.25623.1.0.313817");
  script_version("$Revision: 8510 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-24 08:57:42 +0100 (Wed, 24 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-04-30 14:39:22 +0200 (Fri, 30 Apr 2010)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_xref(name: "MDVSA", value: "2010:084");
  script_cve_id("CVE-2009-3555", "CVE-2010-0082", "CVE-2010-0084", "CVE-2010-0085", "CVE-2010-0088", "CVE-2010-0091", "CVE-2010-0092", "CVE-2010-0093", "CVE-2010-0094", "CVE-2010-0095", "CVE-2010-0837", "CVE-2010-0838", "CVE-2010-0840", "CVE-2010-0845", "CVE-2010-0847", "CVE-2010-0848", "CVE-2009-2409", "CVE-2009-3728", "CVE-2009-3869", "CVE-2009-3871", "CVE-2009-3873", "CVE-2009-3874", "CVE-2009-3875", "CVE-2009-3876", "CVE-2009-3877", "CVE-2009-3879", "CVE-2009-3880", "CVE-2009-3881", "CVE-2009-3882", "CVE-2009-3883", "CVE-2009-3884", "CVE-2009-3885");
  script_name("Mandriva Update for java-1.6.0-openjdk MDVSA-2010:084 (java-1.6.0-openjdk)");

  script_tag(name: "summary" , value: "Check for the Version of java-1.6.0-openjdk");
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

  if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk", rpm:"java-1.6.0-openjdk~1.6.0.0~2.b18.2mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk-demo", rpm:"java-1.6.0-openjdk-demo~1.6.0.0~2.b18.2mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk-devel", rpm:"java-1.6.0-openjdk-devel~1.6.0.0~2.b18.2mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk-javadoc", rpm:"java-1.6.0-openjdk-javadoc~1.6.0.0~2.b18.2mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk-plugin", rpm:"java-1.6.0-openjdk-plugin~1.6.0.0~2.b18.2mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk-src", rpm:"java-1.6.0-openjdk-src~1.6.0.0~2.b18.2mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "MNDK_2010.0")
{

  if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk", rpm:"java-1.6.0-openjdk~1.6.0.0~2.b18.2mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk-demo", rpm:"java-1.6.0-openjdk-demo~1.6.0.0~2.b18.2mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk-devel", rpm:"java-1.6.0-openjdk-devel~1.6.0.0~2.b18.2mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk-javadoc", rpm:"java-1.6.0-openjdk-javadoc~1.6.0.0~2.b18.2mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk-plugin", rpm:"java-1.6.0-openjdk-plugin~1.6.0.0~2.b18.2mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk-src", rpm:"java-1.6.0-openjdk-src~1.6.0.0~2.b18.2mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "MNDK_2009.1")
{

  if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk", rpm:"java-1.6.0-openjdk~1.6.0.0~2.b18.2mdv2009.1", rls:"MNDK_2009.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk-demo", rpm:"java-1.6.0-openjdk-demo~1.6.0.0~2.b18.2mdv2009.1", rls:"MNDK_2009.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk-devel", rpm:"java-1.6.0-openjdk-devel~1.6.0.0~2.b18.2mdv2009.1", rls:"MNDK_2009.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk-javadoc", rpm:"java-1.6.0-openjdk-javadoc~1.6.0.0~2.b18.2mdv2009.1", rls:"MNDK_2009.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk-plugin", rpm:"java-1.6.0-openjdk-plugin~1.6.0.0~2.b18.2mdv2009.1", rls:"MNDK_2009.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk-src", rpm:"java-1.6.0-openjdk-src~1.6.0.0~2.b18.2mdv2009.1", rls:"MNDK_2009.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "MNDK_2009.0")
{

  if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk", rpm:"java-1.6.0-openjdk~1.6.0.0~2.b18.2mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk-demo", rpm:"java-1.6.0-openjdk-demo~1.6.0.0~2.b18.2mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk-devel", rpm:"java-1.6.0-openjdk-devel~1.6.0.0~2.b18.2mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk-javadoc", rpm:"java-1.6.0-openjdk-javadoc~1.6.0.0~2.b18.2mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk-plugin", rpm:"java-1.6.0-openjdk-plugin~1.6.0.0~2.b18.2mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk-src", rpm:"java-1.6.0-openjdk-src~1.6.0.0~2.b18.2mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
