###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for rgmanager CESA-2009:1339 centos5 i386
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
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2009-September/016154.html");
  script_oid("1.3.6.1.4.1.25623.1.0.880743");
  script_version("$Revision: 14222 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $");
  script_tag(name:"creation_date", value:"2011-08-09 08:20:34 +0200 (Tue, 09 Aug 2011)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2008-6552");
  script_name("CentOS Update for rgmanager CESA-2009:1339 centos5 i386");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'rgmanager'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS5");
  script_tag(name:"affected", value:"rgmanager on CentOS 5");
  script_tag(name:"insight", value:"The rgmanager package contains the Red Hat Resource Group Manager, which
  provides high availability for critical server applications in the event of
  system downtime.

  Multiple insecure temporary file use flaws were discovered in rgmanager and
  various resource scripts run by rgmanager. A local attacker could use these
  flaws to overwrite an arbitrary file writable by the rgmanager process
  (i.e. user root) with the output of rgmanager or a resource agent via a
  symbolic link attack. (CVE-2008-6552)

  This update also fixes the following bugs:

  * clulog now accepts '-' as the first character in messages.

  * if expire_time is 0, max_restarts is no longer ignored.

  * the SAP resource agents included in the rgmanager package shipped with
  Red Hat Enterprise Linux 5.3 were outdated. This update includes the most
  recent SAP resource agents and, consequently, improves SAP failover
  support.

  * empty PID files no longer cause resource start failures.

  * recovery policy of type 'restart' now works properly when using a
  resource based on ra-skelet.sh.

  * samba.sh has been updated to kill the PID listed in the proper PID file.

  * handling of the '-F' option has been improved to fix issues causing
  rgmanager to crash if no members of a restricted failover domain were
  online.

  * the number of simultaneous status checks can now be limited to prevent
  load spikes.

  * forking and cloning during status checks has been optimized to reduce
  load spikes.

  * rg_test no longer hangs when run with large cluster configuration files.

  * when rgmanager is used with a restricted failover domain it will no
  longer occasionally segfault when some nodes are offline during a failover
  event.

  * virtual machine guests no longer restart after a cluster.conf update.

  * nfsclient.sh no longer leaves temporary files after running.

  * extra checks from the Oracle agents have been removed.

  * vm.sh now uses libvirt.

  * users can now define an explicit service processing order when
  central_processing is enabled.

  * virtual machine guests can no longer start on 2 nodes at the same time.

  * in some cases a successfully migrated virtual machine guest could restart
  when the cluster.conf file was updated.

  * incorrect reporting of a service being started when it was not started
  has been addressed.

  As well, this update adds the following enhancements:

  * a startup_wait option has been added to the MySQL resource agent.

  * services can now be prioritized.

  * rgmanager now checks to see if it has been killed by the OOM killer and
  if so, reboots the node.

  Users of rgmanager are advised to upgrade to this updated package, which
  resolves these issues and adds these enhancements.");
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

  if ((res = isrpmvuln(pkg:"rgmanager", rpm:"rgmanager~2.0.52~1.el5.centos", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
