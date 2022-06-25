###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_RHSA-2018_0095-01_java-1.8.0-openjdk.nasl 12497 2018-11-23 08:28:21Z cfischer $
#
# RedHat Update for java-1.8.0-openjdk RHSA-2018:0095-01
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.910002");
  script_version("$Revision: 12497 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $");
  script_tag(name:"creation_date", value:"2018-01-18 07:34:59 +0100 (Thu, 18 Jan 2018)");
  script_cve_id("CVE-2018-2579", "CVE-2018-2582", "CVE-2018-2588", "CVE-2018-2599",
                "CVE-2018-2602", "CVE-2018-2603", "CVE-2018-2618", "CVE-2018-2629",
                "CVE-2018-2633", "CVE-2018-2634", "CVE-2018-2637", "CVE-2018-2641",
                "CVE-2018-2663", "CVE-2018-2677", "CVE-2018-2678");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("RedHat Update for java-1.8.0-openjdk RHSA-2018:0095-01");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'java-1.8.0-openjdk'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The java-1.8.0-openjdk packages provide
the OpenJDK 8 Java Runtime Environment and the OpenJDK 8 Java Software Development
Kit.

Security Fix(es):

  * Multiple flaws were found in the Hotspot and AWT components of OpenJDK.
An untrusted Java application or applet could use these flaws to bypass
certain Java sandbox restrictions. (CVE-2018-2582, CVE-2018-2641)

  * It was discovered that the LDAPCertStore class in the JNDI component of
OpenJDK failed to securely handle LDAP referrals. An attacker could
possibly use this flaw to make it fetch attacker controlled certificate
data. (CVE-2018-2633)

  * The JGSS component of OpenJDK ignores the value of the
javax.security.auth.useSubjectCredsOnly property when using HTTP/SPNEGO
authentication and always uses global credentials. It was discovered that
this could cause global credentials to be unexpectedly used by an untrusted
Java application. (CVE-2018-2634)

  * It was discovered that the JMX component of OpenJDK failed to properly
set the deserialization filter for the SingleEntryRegistry in certain
cases. A remote attacker could possibly use this flaw to bypass intended
deserialization restrictions. (CVE-2018-2637)

  * It was discovered that the LDAP component of OpenJDK failed to properly
encode special characters in user names when adding them to an LDAP search
query. A remote attacker could possibly use this flaw to manipulate LDAP
queries performed by the LdapLoginModule class. (CVE-2018-2588)

  * It was discovered that the DNS client implementation in the JNDI
component of OpenJDK did not use random source ports when sending out DNS
queries. This could make it easier for a remote attacker to spoof responses
to those queries. (CVE-2018-2599)

  * It was discovered that the I18n component of OpenJDK could use an
untrusted search path when loading resource bundle classes. A local
attacker could possibly use this flaw to execute arbitrary code as another
local user by making their Java application load an attacker controlled
class file. (CVE-2018-2602)

  * It was discovered that the Libraries component of OpenJDK failed to
sufficiently limit the amount of memory allocated when reading DER encoded
input. A remote attacker could possibly use this flaw to make a Java
application use an excessive amount of memory if it parsed attacker
supplied DER encoded input. (CVE-2018-2603)

  * It was discovered that the key agreement implementations in the JCE
component of OpenJDK did not guarantee sufficie ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"affected", value:"java-1.8.0-openjdk on Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Server (v. 7),
  Red Hat Enterprise Linux Workstation (v. 6)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");

  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2018-January/msg00061.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_(7|6)");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "RHENT_7")
{

  if ((res = isrpmvuln(pkg:"java-1.8.0-openjdk", rpm:"java-1.8.0-openjdk~1.8.0.161~0.b14.el7_4", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1.8.0-openjdk-debuginfo", rpm:"java-1.8.0-openjdk-debuginfo~1.8.0.161~0.b14.el7_4", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1.8.0-openjdk-devel", rpm:"java-1.8.0-openjdk-devel~1.8.0.161~0.b14.el7_4", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1.8.0-openjdk-headless", rpm:"java-1.8.0-openjdk-headless~1.8.0.161~0.b14.el7_4", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "RHENT_6")
{

  if ((res = isrpmvuln(pkg:"java-1.8.0-openjdk", rpm:"java-1.8.0-openjdk~1.8.0.161~3.b14.el6_9", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1.8.0-openjdk-debuginfo", rpm:"java-1.8.0-openjdk-debuginfo~1.8.0.161~3.b14.el6_9", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1.8.0-openjdk-devel", rpm:"java-1.8.0-openjdk-devel~1.8.0.161~3.b14.el6_9", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1.8.0-openjdk-headless", rpm:"java-1.8.0-openjdk-headless~1.8.0.161~3.b14.el6_9", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
