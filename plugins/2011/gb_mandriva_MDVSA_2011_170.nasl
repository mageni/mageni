###############################################################################
# OpenVAS Vulnerability Test
#
# Mandriva Update for java-1.6.0-openjdk MDVSA-2011:170 (java-1.6.0-openjdk)
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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

if(description)
{
  script_xref(name:"URL", value:"http://lists.mandriva.com/security-announce/2011-11/msg00014.php");
  script_oid("1.3.6.1.4.1.25623.1.0.831493");
  script_version("$Revision: 12381 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-16 12:16:30 +0100 (Fri, 16 Nov 2018) $");
  script_tag(name:"creation_date", value:"2011-11-14 10:49:09 +0530 (Mon, 14 Nov 2011)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2011-3547", "CVE-2011-3548", "CVE-2011-3551", "CVE-2011-3552",
                "CVE-2011-3553", "CVE-2011-3544", "CVE-2011-3521", "CVE-2011-3554",
                "CVE-2011-3389", "CVE-2011-3558", "CVE-2011-3556", "CVE-2011-3557",
                "CVE-2011-3560", "CVE-2011-3377");
  script_name("Mandriva Update for java-1.6.0-openjdk MDVSA-2011:170 (java-1.6.0-openjdk)");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'java-1.6.0-openjdk'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Mandrake Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mandriva_mandrake_linux", "ssh/login/release", re:"ssh/login/release=MNDK_(mes5|2010\.1)");
  script_tag(name:"affected", value:"java-1.6.0-openjdk on Mandriva Linux 2010.1,
  Mandriva Linux 2010.1/X86_64,
  Mandriva Enterprise Server 5,
  Mandriva Enterprise Server 5/X86_64");
  script_tag(name:"insight", value:"Security issues were identified and fixed in openjdk (icedtea6)
  and icedtea-web:

  IcedTea6 prior to 1.10.4 allows remote untrusted Java Web Start
  applications and untrusted Java applets to affect confidentiality
  via unknown vectors related to Networking (CVE-2011-3547).

  IcedTea6 prior to 1.10.4 allows remote untrusted Java Web Start
  applications and untrusted Java applets to affect confidentiality,
  integrity, and availability, related to AWT (CVE-2011-3548).

  IcedTea6 prior to 1.10.4 allows remote attackers to affect
  confidentiality, integrity, and availability via unknown vectors
  related to 2D (CVE-2011-3551).

  IcedTea6 prior to 1.10.4 allows remote attackers to affect integrity
  via unknown vectors related to Networking (CVE-2011-3552).

  IcedTea6 prior to 1.10.4 allows remote authenticated users to affect
  confidentiality, related to JAXWS (CVE-2011-3553).

  IcedTea6 prior to 1.10.4 allows remote untrusted Java Web Start
  applications and untrusted Java applets to affect confidentiality,
  integrity, and availability via unknown vectors related to Scripting
  (CVE-2011-3544).

  IcedTea6 prior to 1.10.4 allows remote untrusted Java Web Start
  applications and untrusted Java applets to affect confidentiality,
  integrity, and availability via unknown vectors related to
  Deserialization (CVE-2011-3521).

  IcedTea6 prior to 1.10.4 allows remote untrusted Java Web Start
  applications and untrusted Java applets to affect confidentiality,
  integrity, and availability via unknown vectors (CVE-2011-3554).

  A flaw was found in the way the SSL 3 and TLS 1.0 protocols used
  block ciphers in cipher-block chaining (CBC) mode. An attacker able
  to perform a chosen plain text attack against a connection mixing
  trusted and untrusted data could use this flaw to recover portions
  of the trusted data sent over the connection (CVE-2011-3389).

  Note: This update mitigates the CVE-2011-3389 issue by splitting
  the first application data record byte to a separate SSL/TLS
  protocol record. This mitigation may cause compatibility issues
  with some SSL/TLS implementations and can be disabled using the
  jsse.enableCBCProtection boolean property. This can be done on the
  command line by appending the flag -Djsse.enableCBCProtection=false
  to the java command.

  IcedTea6 prior to 1.10.4 allows remote untrusted Java Web Start
  applications and untrusted Java applets to affect confidentiality
  via unknown vectors related to Hot ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "MNDK_mes5")
{

  if ((res = isrpmvuln(pkg:"icedtea-web", rpm:"icedtea-web~1.0.6~0.1mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk-1.6.0.0", rpm:"java-1.6.0-openjdk-1.6.0.0~24.b22.1mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk-demo", rpm:"java-1.6.0-openjdk-demo~1.6.0.0~24.b22.1mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk-devel", rpm:"java-1.6.0-openjdk-devel~1.6.0.0~24.b22.1mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk-javadoc", rpm:"java-1.6.0-openjdk-javadoc~1.6.0.0~24.b22.1mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk-src", rpm:"java-1.6.0-openjdk-src~1.6.0.0~24.b22.1mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "MNDK_2010.1")
{

  if ((res = isrpmvuln(pkg:"icedtea-web", rpm:"icedtea-web~1.0.6~0.1mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk", rpm:"java-1.6.0-openjdk~1.6.0.0~24.b22.1mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk-demo", rpm:"java-1.6.0-openjdk-demo~1.6.0.0~24.b22.1mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk-devel", rpm:"java-1.6.0-openjdk-devel~1.6.0.0~24.b22.1mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk-javadoc", rpm:"java-1.6.0-openjdk-javadoc~1.6.0.0~24.b22.1mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk-src", rpm:"java-1.6.0-openjdk-src~1.6.0.0~24.b22.1mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
