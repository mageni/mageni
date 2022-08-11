###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for kdenetwork RHSA-2014:1827-01
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.871290");
  script_version("$Revision: 12497 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $");
  script_tag(name:"creation_date", value:"2014-11-12 06:23:50 +0100 (Wed, 12 Nov 2014)");
  script_cve_id("CVE-2014-6053", "CVE-2014-6054", "CVE-2014-6055");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_name("RedHat Update for kdenetwork RHSA-2014:1827-01");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'kdenetwork'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The kdenetwork packages contain networking applications for the K Desktop
Environment (KDE). Krfb Desktop Sharing, which is a part of the kdenetwork
package, is a server application that allows session sharing between users.
Krfb uses the LibVNCServer library.

A NULL pointer dereference flaw was found in the way LibVNCServer handled
certain ClientCutText message. A remote attacker could use this flaw to
crash the VNC server by sending a specially crafted ClientCutText message
from a VNC client. (CVE-2014-6053)

A divide-by-zero flaw was found in the way LibVNCServer handled the scaling
factor when it was set to '0'. A remote attacker could use this flaw to
crash the VNC server using a malicious VNC client. (CVE-2014-6054)

Two stack-based buffer overflow flaws were found in the way LibVNCServer
handled file transfers. A remote attacker could use this flaw to crash the
VNC server using a malicious VNC client. (CVE-2014-6055)

Red Hat would like to thank oCERT for reporting these issues. oCERT
acknowledges Nicolas Ruff as the original reporter.

Note: Prior to this update, the kdenetwork packages used an embedded copy
of the LibVNCServer library. With this update, the kdenetwork packages have
been modified to use the system LibVNCServer packages. Therefore, the
update provided by RHSA-2014:1826 must be installed to fully address the
issues in krfb described above.

All kdenetwork users are advised to upgrade to these updated packages,
which contain backported patches to correct these issues. All running
instances of the krfb server must be restarted for this update to take
effect.");
  script_tag(name:"affected", value:"kdenetwork on Red Hat Enterprise Linux Server (v. 7)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2014-November/msg00025.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_7");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "RHENT_7")
{

  if ((res = isrpmvuln(pkg:"kdenetwork-common", rpm:"kdenetwork-common~4.10.5~8.el7_0", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kdenetwork-devel", rpm:"kdenetwork-devel~4.10.5~8.el7_0", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kdenetwork-debuginfo", rpm:"kdenetwork-debuginfo~4.10.5~8.el7_0", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kdenetwork-kdnssd", rpm:"kdenetwork-kdnssd~4.10.5~8.el7_0", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kdenetwork-kget", rpm:"kdenetwork-kget~4.10.5~8.el7_0", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kdenetwork-kget-libs", rpm:"kdenetwork-kget-libs~4.10.5~8.el7_0", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kdenetwork-kopete", rpm:"kdenetwork-kopete~4.10.5~8.el7_0", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kdenetwork-kopete-devel", rpm:"kdenetwork-kopete-devel~4.10.5~8.el7_0", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kdenetwork-kopete-libs", rpm:"kdenetwork-kopete-libs~4.10.5~8.el7_0", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kdenetwork-krdc", rpm:"kdenetwork-krdc~4.10.5~8.el7_0", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kdenetwork-krdc-devel", rpm:"kdenetwork-krdc-devel~4.10.5~8.el7_0", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kdenetwork-krdc-libs", rpm:"kdenetwork-krdc-libs~4.10.5~8.el7_0", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kdenetwork-krfb", rpm:"kdenetwork-krfb~4.10.5~8.el7_0", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kdenetwork-krfb-libs", rpm:"kdenetwork-krfb-libs~4.10.5~8.el7_0", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
