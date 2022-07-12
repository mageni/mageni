###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for exim CESA-2011:0153 centos5 i386
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
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2011-April/017338.html");
  script_oid("1.3.6.1.4.1.25623.1.0.880502");
  script_version("$Revision: 14222 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $");
  script_tag(name:"creation_date", value:"2011-08-09 08:20:34 +0200 (Tue, 09 Aug 2011)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2010-4345");
  script_name("CentOS Update for exim CESA-2011:0153 centos5 i386");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'exim'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS5");
  script_tag(name:"affected", value:"exim on CentOS 5");
  script_tag(name:"insight", value:"Exim is a mail transport agent (MTA) developed at the University of
  Cambridge for use on UNIX systems connected to the Internet.

  A privilege escalation flaw was discovered in Exim. If an attacker were
  able to gain access to the 'exim' user, they could cause Exim to execute
  arbitrary commands as the root user. (CVE-2010-4345)

  This update adds a new configuration file, '/etc/exim/trusted-configs'. To
  prevent Exim from running arbitrary commands as root, Exim will now drop
  privileges when run with a configuration file not listed as trusted. This
  could break backwards compatibility with some Exim configurations, as the
  trusted-configs file only trusts '/etc/exim/exim.conf' and
  '/etc/exim/exim4.conf' by default. If you are using a configuration file
  not listed in the new trusted-configs file, you will need to add it
  manually.

  Additionally, Exim will no longer allow a user to execute exim as root with
  the -D command line option to override macro definitions. All macro
  definitions that require root permissions must now reside in a trusted
  configuration file.

  Users of Exim are advised to upgrade to these updated packages, which
  contain a backported patch to correct this issue. After installing this
  update, the exim daemon will be restarted automatically.");
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

  if ((res = isrpmvuln(pkg:"exim", rpm:"exim~4.63~5.el5_6.2", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"exim-mon", rpm:"exim-mon~4.63~5.el5_6.2", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"exim-sa", rpm:"exim-sa~4.63~5.el5_6.2", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
