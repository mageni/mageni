###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for ipa RHSA-2011:1533-04
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2011-December/msg00008.html");
  script_oid("1.3.6.1.4.1.25623.1.0.870712");
  script_version("$Revision: 12497 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $");
  script_tag(name:"creation_date", value:"2012-07-09 10:51:53 +0530 (Mon, 09 Jul 2012)");
  script_cve_id("CVE-2011-3636");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("RedHat Update for ipa RHSA-2011:1533-04");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ipa'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_6");
  script_tag(name:"affected", value:"ipa on Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"Red Hat Identity Management is a centralized authentication, identity
  management and authorization solution for both traditional and cloud based
  enterprise environments. It integrates components of the Red Hat Directory
  Server, MIT Kerberos, Red Hat Certificate System, NTP and DNS. It provides
  web browser and command-line interfaces. Its administration tools allow an
  administrator to quickly install, set up, and administer a group of domain
  controllers to meet the authentication and identity management requirements
  of large scale Linux and UNIX deployments.

  A Cross-Site Request Forgery (CSRF) flaw was found in Red Hat Identity
  Management. If a remote attacker could trick a user, who was logged into
  the management web interface, into visiting a specially-crafted URL, the
  attacker could perform Red Hat Identity Management configuration changes
  with the privileges of the logged in user. (CVE-2011-3636)

  Due to the changes required to fix CVE-2011-3636, client tools will need to
  be updated for client systems to communicate with updated Red Hat Identity
  Management servers. New client systems will need to have the updated
  ipa-client package installed to be enrolled. Already enrolled client
  systems will need to have the updated certmonger package installed to be
  able to renew their system certificate. Note that system certificates are
  valid for two years by default.

  Updated ipa-client and certmonger packages for Red Hat Enterprise Linux 6
  were released as part of Red Hat Enterprise Linux 6.2. Future updates will
  provide updated packages for Red Hat Enterprise Linux 5.

  This update includes several bug fixes. Space precludes documenting all of
  these changes in this advisory. Users are directed to the Red Hat
  Enterprise Linux 6.2 Technical Notes for information on the most
  significant of these changes, linked to in the References section.

  Users of Red Hat Identity Management should upgrade to these updated
  packages, which correct these issues.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "RHENT_6")
{

  if ((res = isrpmvuln(pkg:"ipa-admintools", rpm:"ipa-admintools~2.1.3~9.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ipa-client", rpm:"ipa-client~2.1.3~9.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ipa-debuginfo", rpm:"ipa-debuginfo~2.1.3~9.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ipa-python", rpm:"ipa-python~2.1.3~9.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ipa-server", rpm:"ipa-server~2.1.3~9.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ipa-server-selinux", rpm:"ipa-server-selinux~2.1.3~9.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
