###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for libvncserver CESA-2014:1826 centos6
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
  script_oid("1.3.6.1.4.1.25623.1.0.882078");
  script_version("$Revision: 14058 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-08 14:25:52 +0100 (Fri, 08 Mar 2019) $");
  script_tag(name:"creation_date", value:"2014-11-12 06:24:12 +0100 (Wed, 12 Nov 2014)");
  script_cve_id("CVE-2014-6051", "CVE-2014-6052", "CVE-2014-6053", "CVE-2014-6054", "CVE-2014-6055");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("CentOS Update for libvncserver CESA-2014:1826 centos6");

  script_tag(name:"summary", value:"Check the version of libvncserver");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"LibVNCServer is a library that allows for easy
creation of VNC server or client functionality.

An integer overflow flaw, leading to a heap-based buffer overflow, was
found in the way screen sizes were handled by LibVNCServer. A malicious VNC
server could use this flaw to cause a client to crash or, potentially,
execute arbitrary code in the client. (CVE-2014-6051)

A NULL pointer dereference flaw was found in LibVNCServer's framebuffer
setup. A malicious VNC server could use this flaw to cause a VNC client to
crash. (CVE-2014-6052)

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

All libvncserver users are advised to upgrade to these updated packages,
which contain backported patches to correct these issues. All running
applications linked against libvncserver must be restarted for this update
to take effect.");
  script_tag(name:"affected", value:"libvncserver on CentOS 6");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2014-November/020747.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS6");
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

  if ((res = isrpmvuln(pkg:"libvncserver", rpm:"libvncserver~0.9.7~7.el6_6.1", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libvncserver-devel", rpm:"libvncserver-devel~0.9.7~7.el6_6.1", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
