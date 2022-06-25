###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for dnsmasq CESA-2009:1238 centos5 i386
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
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2009-September/016119.html");
  script_oid("1.3.6.1.4.1.25623.1.0.880761");
  script_version("$Revision: 14222 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $");
  script_tag(name:"creation_date", value:"2011-08-09 08:20:34 +0200 (Tue, 09 Aug 2011)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2009-2957", "CVE-2009-2958");
  script_name("CentOS Update for dnsmasq CESA-2009:1238 centos5 i386");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'dnsmasq'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS5");
  script_tag(name:"affected", value:"dnsmasq on CentOS 5");
  script_tag(name:"insight", value:"Dnsmasq is a lightweight and easy to configure DNS forwarder and DHCP
  server.

  Core Security Technologies discovered a heap overflow flaw in dnsmasq when
  the TFTP service is enabled (the '--enable-tftp' command line option, or by
  enabling 'enable-tftp' in '/etc/dnsmasq.conf'). If the configured tftp-root
  is sufficiently long, and a remote user sends a request that sends a long
  file name, dnsmasq could crash or, possibly, execute arbitrary code with
  the privileges of the dnsmasq service (usually the unprivileged 'nobody'
  user). (CVE-2009-2957)

  A NULL pointer dereference flaw was discovered in dnsmasq when the TFTP
  service is enabled. This flaw could allow a malicious TFTP client to crash
  the dnsmasq service. (CVE-2009-2958)

  Note: The default tftp-root is '/var/ftpd', which is short enough to make
  it difficult to exploit the CVE-2009-2957 issue. If a longer directory name
  is used, arbitrary code execution may be possible. As well, the dnsmasq
  package distributed by Red Hat does not have TFTP support enabled by
  default.

  All users of dnsmasq should upgrade to this updated package, which contains
  a backported patch to correct these issues. After installing the updated
  package, the dnsmasq service must be restarted for the update to take
  effect.");
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

  if ((res = isrpmvuln(pkg:"dnsmasq", rpm:"dnsmasq~2.45~1.1.el5_3", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
