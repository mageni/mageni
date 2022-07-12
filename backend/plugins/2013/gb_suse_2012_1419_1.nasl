###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2012_1419_1.nasl 12497 2018-11-23 08:28:21Z cfischer $
#
# SuSE Update for java-1_7_0-openjdk openSUSE-SU-2012:1419-1 (java-1_7_0-openjdk)
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2012-10/msg00020.html");
  script_oid("1.3.6.1.4.1.25623.1.0.850421");
  script_version("$Revision: 12497 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $");
  script_tag(name:"creation_date", value:"2013-03-11 18:29:55 +0530 (Mon, 11 Mar 2013)");
  script_cve_id("CVE-2012-3216", "CVE-2012-4416", "CVE-2012-5068", "CVE-2012-5069",
                "CVE-2012-5070", "CVE-2012-5071", "CVE-2012-5073", "CVE-2012-5074",
                "CVE-2012-5075", "CVE-2012-5076", "CVE-2012-5077", "CVE-2012-5084",
                "CVE-2012-5085", "CVE-2012-5086", "CVE-2012-5087", "CVE-2012-5088",
                "CVE-2012-5089", "CVE-2012-5072", "CVE-2012-5081", "CVE-2012-5079");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("SuSE Update for java-1_7_0-openjdk openSUSE-SU-2012:1419-1 (java-1_7_0-openjdk)");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'java-1_7_0-openjdk'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSE12\.2");
  script_tag(name:"affected", value:"java-1_7_0-openjdk on openSUSE 12.2");
  script_tag(name:"insight", value:"java-1_7_0-opendjk was updated to icedtea-2.3.3 (bnc#785814)

  * Security fixes

  - S6631398, CVE-2012-3216: FilePermission improved path
  checking

  - S7093490: adjust package access in rmiregistry

  - S7143535, CVE-2012-5068: ScriptEngine corrected
  permissions

  - S7158796, CVE-2012-5070: Tighten properties checking in
  EnvHelp

  - S7158807: Revise stack management with volatile call
  sites

  - S7163198, CVE-2012-5076: Tightened package accessibility

  - S7167656, CVE-2012-5077: Multiple Seeders are being
  created

  - S7169884, CVE-2012-5073: LogManager checks do not work
  correctly for sub-types

  - S7169887, CVE-2012-5074: Tightened package accessibility

  - S7169888, CVE-2012-5075: Narrowing resource definitions
  in JMX RMI connector

  - S7172522, CVE-2012-5072: Improve DomainCombiner checking

  - S7186286, CVE-2012-5081: TLS implementation to better
  adhere to RFC

  - S7189103, CVE-2012-5069: Executors needs to maintain
  state

  - S7189490: More improvements to DomainCombiner checking

  - S7189567, CVE-2012-5085: java net obsolete protocol

  - S7192975, CVE-2012-5071: Issue with JMX reflection

  - S7195194, CVE-2012-5084: Better data validation for
  Swing

  - S7195549, CVE-2012-5087: Better bean object persistence

  - S7195917, CVE-2012-5086: XMLDecoder parsing at
  close-time should be improved

  - S7195919, CVE-2012-5079: (sl) ServiceLoader can throw
  CCE without needing to create instance

  - S7196190, CVE-2012-5088: Improve method of handling
  MethodHandles

  - S7198296, CVE-2012-5089: Refactor classloader usage

  - S7158800: Improve storage of symbol tables

  - S7158801: Improve VM CompileOnly option

  - S7158804: Improve config file parsing

  - S7198606, CVE-2012-4416: Improve VM optimization

  * Bug fixes

  - Remove merge artefact.");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);
res = "";

if(release == "openSUSE12.2")
{

  if ((res = isrpmvuln(pkg:"java-1_7_0-openjdk", rpm:"java-1_7_0-openjdk~1.7.0.6~3.16.1", rls:"openSUSE12.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1_7_0-openjdk-debuginfo", rpm:"java-1_7_0-openjdk-debuginfo~1.7.0.6~3.16.1", rls:"openSUSE12.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1_7_0-openjdk-debugsource", rpm:"java-1_7_0-openjdk-debugsource~1.7.0.6~3.16.1", rls:"openSUSE12.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1_7_0-openjdk-demo", rpm:"java-1_7_0-openjdk-demo~1.7.0.6~3.16.1", rls:"openSUSE12.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1_7_0-openjdk-demo-debuginfo", rpm:"java-1_7_0-openjdk-demo-debuginfo~1.7.0.6~3.16.1", rls:"openSUSE12.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1_7_0-openjdk-devel", rpm:"java-1_7_0-openjdk-devel~1.7.0.6~3.16.1", rls:"openSUSE12.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1_7_0-openjdk-devel-debuginfo", rpm:"java-1_7_0-openjdk-devel-debuginfo~1.7.0.6~3.16.1", rls:"openSUSE12.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1_7_0-openjdk-javadoc", rpm:"java-1_7_0-openjdk-javadoc~1.7.0.6~3.16.1", rls:"openSUSE12.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1_7_0-openjdk-src", rpm:"java-1_7_0-openjdk-src~1.7.0.6~3.16.1", rls:"openSUSE12.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
