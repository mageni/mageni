###############################################################################
# OpenVAS Vulnerability Test
#
# Mandriva Update for java-1.6.0-openjdk MDVSA-2012:150-1 (java-1.6.0-openjdk)
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_xref(name:"URL", value:"http://www.mandriva.com/en/support/security/advisories/?name=MDVSA-2012:150-1");
  script_oid("1.3.6.1.4.1.25623.1.0.831743");
  script_version("$Revision: 12381 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-16 12:16:30 +0100 (Fri, 16 Nov 2018) $");
  script_tag(name:"creation_date", value:"2012-10-09 10:01:55 +0530 (Tue, 09 Oct 2012)");
  script_cve_id("CVE-2012-0547", "CVE-2012-3136", "CVE-2012-1682");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Mandriva Update for java-1.6.0-openjdk MDVSA-2012:150-1 (java-1.6.0-openjdk)");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'java-1.6.0-openjdk'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Mandrake Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mandriva_mandrake_linux", "ssh/login/release", re:"ssh/login/release=MNDK_2011\.0");
  script_tag(name:"affected", value:"java-1.6.0-openjdk on Mandriva Linux 2011.0");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"Multiple security issues were identified and fixed in OpenJDK
  (icedtea6):

  Unspecified vulnerability in the Java Runtime Environment (JRE)
  component in Oracle Java SE 7 Update 6 and earlier, and 6 Update 34
  and earlier, has no impact and remote attack vectors involving AWT
  and a security-in-depth issue that is not directly exploitable but
  which can be used to aggravate security vulnerabilities that can be
  directly exploited. NOTE: this identifier was assigned by the Oracle
  CNA, but CVE is not intended to cover defense-in-depth issues that are
  only exposed by the presence of other vulnerabilities (CVE-2012-0547).

  Unspecified vulnerability in the Java Runtime Environment (JRE)
  component in Oracle Java SE 7 Update 6 and earlier allows remote
  attackers to affect confidentiality, integrity, and availability
  via unknown vectors related to Beans, a different vulnerability than
  CVE-2012-3136 (CVE-2012-1682).

  The updated packages provides icedtea6-1.11.4 which is not vulnerable
  to these issues.

  Update:

  Packages for Mandriva Linux 2011 is being provided.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "MNDK_2011.0")
{

  if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk", rpm:"java-1.6.0-openjdk~1.6.0.0~34.b24.1", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk-demo", rpm:"java-1.6.0-openjdk-demo~1.6.0.0~34.b24.1", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk-devel", rpm:"java-1.6.0-openjdk-devel~1.6.0.0~34.b24.1", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk-javadoc", rpm:"java-1.6.0-openjdk-javadoc~1.6.0.0~34.b24.1", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
