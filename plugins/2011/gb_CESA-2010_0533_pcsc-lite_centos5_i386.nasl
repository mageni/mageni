###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for pcsc-lite CESA-2010:0533 centos5 i386
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
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2010-July/016783.html");
  script_oid("1.3.6.1.4.1.25623.1.0.880610");
  script_version("$Revision: 14222 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $");
  script_tag(name:"creation_date", value:"2011-08-09 08:20:34 +0200 (Tue, 09 Aug 2011)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_cve_id("CVE-2009-4901", "CVE-2010-0407", "CVE-2009-4902");
  script_name("CentOS Update for pcsc-lite CESA-2010:0533 centos5 i386");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'pcsc-lite'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS5");
  script_tag(name:"affected", value:"pcsc-lite on CentOS 5");
  script_tag(name:"insight", value:"PC/SC Lite provides a Windows SCard compatible interface for communicating
  with smart cards, smart card readers, and other security tokens.

  Multiple buffer overflow flaws were discovered in the way the pcscd daemon,
  a resource manager that coordinates communications with smart card readers
  and smart cards connected to the system, handled client requests. A local
  user could create a specially-crafted request that would cause the pcscd
  daemon to crash or, possibly, execute arbitrary code. (CVE-2010-0407,
  CVE-2009-4901)

  Users of pcsc-lite should upgrade to these updated packages, which contain
  a backported patch to correct these issues. After installing this update,
  the pcscd daemon will be restarted automatically.");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "CentOS5")
{

  if ((res = isrpmvuln(pkg:"pcsc-lite", rpm:"pcsc-lite~1.4.4~4.el5_5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"pcsc-lite-devel", rpm:"pcsc-lite-devel~1.4.4~4.el5_5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"pcsc-lite-doc", rpm:"pcsc-lite-doc~1.4.4~4.el5_5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"pcsc-lite-libs", rpm:"pcsc-lite-libs~1.4.4~4.el5_5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
