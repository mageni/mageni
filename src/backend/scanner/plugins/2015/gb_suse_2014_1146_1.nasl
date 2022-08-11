###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2014_1146_1.nasl 12381 2018-11-16 11:16:30Z cfischer $
#
# SuSE Update for dbus-1 SUSE-SU-2014:1146-1 (dbus-1)
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.850764");
  script_version("$Revision: 12381 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-16 12:16:30 +0100 (Fri, 16 Nov 2018) $");
  script_tag(name:"creation_date", value:"2015-10-13 18:35:00 +0530 (Tue, 13 Oct 2015)");
  script_cve_id("CVE-2014-3638", "CVE-2014-3639");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for dbus-1 SUSE-SU-2014:1146-1 (dbus-1)");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'dbus-1'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Various denial of service issues were fixed in the DBUS service.

  * CVE-2014-3638: dbus-daemon tracks whether method call messages
  expect a reply, so that unsolicited replies can be dropped. As
  currently implemented, if there are n parallel method calls in
  progress, each method reply takes O(n) CPU time. A malicious user
  could exploit this by opening the maximum allowed number of parallel
  connections and sending the maximum number of parallel method calls
  on each one, causing subsequent method calls to be unreasonably
  slow, a denial of service.

  * CVE-2014-3639: dbus-daemon allows a small number of 'incomplete'
  connections (64 by default) whose identity has not yet been
  confirmed. When this limit has been reached, subsequent connections
  are dropped. Alban's testing indicates that one malicious process
  that makes repeated connection attempts, but never completes the
  authentication handshake and instead waits for dbus-daemon to time
  out and disconnect it, can cause the majority of legitimate
  connection attempts to fail.");

  script_tag(name:"affected", value:"dbus-1 on SUSE Linux Enterprise Server 11 SP3");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=SLES11\.0SP3");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);
res = "";

if(release == "SLES11.0SP3")
{

  if ((res = isrpmvuln(pkg:"dbus-1", rpm:"dbus-1~1.2.10~3.31.1", rls:"SLES11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"dbus-1-x11", rpm:"dbus-1-x11~1.2.10~3.31.1", rls:"SLES11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"dbus-1-32bit", rpm:"dbus-1-32bit~1.2.10~3.31.1", rls:"SLES11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"dbus-1-x86", rpm:"dbus-1-x86~1.2.10~3.31.1", rls:"SLES11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
