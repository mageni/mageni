###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for pcsc-lite CESA-2013:0525 centos6
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
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2013-March/019466.html");
  script_oid("1.3.6.1.4.1.25623.1.0.881634");
  script_version("$Revision: 14222 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $");
  script_tag(name:"creation_date", value:"2013-03-12 09:58:55 +0530 (Tue, 12 Mar 2013)");
  script_cve_id("CVE-2010-4531");
  script_tag(name:"cvss_base", value:"4.4");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_name("CentOS Update for pcsc-lite CESA-2013:0525 centos6");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'pcsc-lite'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS6");
  script_tag(name:"affected", value:"pcsc-lite on CentOS 6");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"insight", value:"PC/SC Lite provides a Windows SCard compatible interface for communicating
  with smart cards, smart card readers, and other security tokens.

  A stack-based buffer overflow flaw was found in the way pcsc-lite decoded
  certain attribute values of Answer-to-Reset (ATR) messages. A local
  attacker could use this flaw to execute arbitrary code with the privileges
  of the user running the pcscd daemon (root, by default), by inserting a
  specially-crafted smart card. (CVE-2010-4531)

  This update also fixes the following bugs:

  * Due to an error in the init script, the chkconfig utility did not
  automatically place the pcscd init script after the start of the HAL
  daemon. Consequently, the pcscd service did not start automatically at boot
  time. With this update, the pcscd init script has been changed to
  explicitly start only after HAL is up, thus fixing this bug. (BZ#788474,
  BZ#814549)

  * Because the chkconfig settings and the startup files in the /etc/rc.d/
  directory were not changed during the update described in the
  RHBA-2012:0990 advisory, the user had to update the chkconfig settings
  manually to fix the problem. Now, the chkconfig settings and the startup
  files in the /etc/rc.d/ directory are automatically updated as expected.
  (BZ#834803)

  * Previously, the SCardGetAttrib() function did not work properly and
  always returned the 'SCARD_E_INSUFFICIENT_BUFFER' error regardless of the
  actual buffer size. This update applies a patch to fix this bug and the
  SCardGetAttrib() function now works as expected. (BZ#891852)

  All users of pcsc-lite are advised to upgrade to these updated packages,
  which fix these issues. After installing this update, the pcscd daemon will
  be restarted automatically.");
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

if(release == "CentOS6")
{

  if ((res = isrpmvuln(pkg:"pcsc-lite", rpm:"pcsc-lite~1.5.2~11.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"pcsc-lite-devel", rpm:"pcsc-lite-devel~1.5.2~11.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"pcsc-lite-doc", rpm:"pcsc-lite-doc~1.5.2~11.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"pcsc-lite-libs", rpm:"pcsc-lite-libs~1.5.2~11.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
