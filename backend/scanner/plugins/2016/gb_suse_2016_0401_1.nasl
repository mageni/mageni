###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2016_0401_1.nasl 12381 2018-11-16 11:16:30Z cfischer $
#
# SuSE Update for java-1_7_1-ibm SUSE-SU-2016:0401-1 (java-1_7_1-ibm)
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.851203");
  script_version("$Revision: 12381 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-16 12:16:30 +0100 (Fri, 16 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-02-11 06:41:34 +0100 (Thu, 11 Feb 2016)");
  script_cve_id("CVE-2015-5041", "CVE-2015-7575", "CVE-2015-7981", "CVE-2015-8126",
                "CVE-2015-8472", "CVE-2015-8540", "CVE-2016-0402", "CVE-2016-0448",
                "CVE-2016-0466", "CVE-2016-0483", "CVE-2016-0494");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for java-1_7_1-ibm SUSE-SU-2016:0401-1 (java-1_7_1-ibm)");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'java-1_7_1-ibm'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"This update for java-1_7_1-ibm fixes the following issues by updating to
  7.1-3.30 (bsc#963937):


  - CVE-2015-5041: Could could have invoked non-public interface methods
  under certain circumstances

  - CVE-2015-7575: The TLS protocol could allow weaker than expected
  security caused by a collision attack when using the MD5 hash function
  for signing a ServerKeyExchange message during a TLS handshake. An
  attacker could exploit this vulnerability using man-in-the-middle
  techniques to impersonate a TLS server and obtain credentials

  - CVE-2015-7981: libpng could allow a remote attacker to obtain sensitive
  information, caused by an out-of-bounds read in the
  png_convert_to_rfc1123 function. An attacker could exploit this
  vulnerability to obtain sensitive information

  - CVE-2015-8126: buffer overflow in libpng caused by improper bounds
  checking by the png_set_PLTE() and png_get_PLTE() functions

  - CVE-2015-8472: buffer overflow in libpng caused by improper bounds
  checking by the png_set_PLTE() and png_get_PLTE() functions

  - CVE-2015-8540: libpng is vulnerable to a buffer overflow, caused by a
  read underflow in png_check_keyword in pngwutil.c. By sending an overly
  long argument, a remote attacker could overflow a buffer and execute
  arbitrary code on the system or cause the application to crash.

  - CVE-2016-0402: An unspecified vulnerability related to the Networking
  component has no confidentiality impact, partial integrity impact, and
  no availability impact

  - CVE-2016-0448: An unspecified vulnerability related to the JMX component
  could allow a remote attacker to obtain sensitive information

  - CVE-2016-0466: An unspecified vulnerability related to the JAXP
  component could allow a remote attacker to cause a denial of service

  - CVE-2016-0483: An unspecified vulnerability related to the AWT component
  has complete confidentiality impact, complete integrity impact, and
  complete availability impact

  - CVE-2016-0494: An unspecified vulnerability related to the 2D component
  has complete confidentiality impact, complete integrity impact, and
  complete availability impact

  The following bugs were fixed:

  - bsc#960402: resolve package conflicts in devel package");
  script_tag(name:"affected", value:"java-1_7_1-ibm on SUSE Linux Enterprise Server 12");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=SLES12\.0SP0");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);
res = "";

if(release == "SLES12.0SP0")
{

  if ((res = isrpmvuln(pkg:"java-1_7_1-ibm", rpm:"java-1_7_1-ibm~1.7.1_sr3.30~21.1", rls:"SLES12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1_7_1-ibm-jdbc", rpm:"java-1_7_1-ibm-jdbc~1.7.1_sr3.30~21.1", rls:"SLES12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1_7_1-ibm-alsa", rpm:"java-1_7_1-ibm-alsa~1.7.1_sr3.30~21.1", rls:"SLES12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1_7_1-ibm-plugin", rpm:"java-1_7_1-ibm-plugin~1.7.1_sr3.30~21.1", rls:"SLES12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
