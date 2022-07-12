###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for ipa RHSA-2013:0528-02
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
  script_tag(name:"affected", value:"ipa on Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"Red Hat Identity Management is a centralized authentication, identity
  management and authorization solution for both traditional and cloud-based
  enterprise environments. It integrates components of the Red Hat Directory
  Server, MIT Kerberos, Red Hat Certificate System, NTP, and DNS. It provides
  web browser and command-line interfaces. Its administration tools allow an
  administrator to quickly install, set up, and administer a group of domain
  controllers to meet the authentication and identity management requirements
  of large-scale Linux and UNIX deployments.

  It was found that the current default configuration of IPA servers did not
  publish correct CRLs (Certificate Revocation Lists). The default
  configuration specifies that every replica is to generate its own CRL.
  however, this can result in inconsistencies in the CRL contents provided to
  clients from different Identity Management replicas. More specifically, if
  a certificate is revoked on one Identity Management replica, it will not
  show up on another Identity Management replica. (CVE-2012-4546)

  These updated ipa packages also include numerous bug fixes and
  enhancements. Space precludes documenting all of these changes in this
  advisory. Users are directed to the Red Hat Enterprise Linux 6.4 Technical
  Notes, linked to in the References, for information on the most significant
  of these changes.

  Users are advised to upgrade to these updated ipa packages, which fix these
  issues and add these enhancements.

  4. Solution:

  Before applying this update, make sure all previously-released errata
  relevant to your system have been applied.

  This update is available via the Red Hat Network. Details on how to
  use the Red Hat Network to apply this update are available at the references.

  5. Bugs fixed:

  748987 - If  master has leftover replica agreement from a previous failed
           attempt, next replica install can fail
  766095 - [RFE] UI for SELinux user mapping
  767723 - [RFE] Implement ipa web GUI to create trusts
  768510 - migrate-ds : misleading error message when invalid objectclass defined
  773490 - dns discovery domain needs to be added to sssd.conf
  781208 - ipa user-find --manager does not find matches
  782847 - ipa permission- ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2013-February/msg00065.html");
  script_oid("1.3.6.1.4.1.25623.1.0.870938");
  script_version("$Revision: 14114 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-12 12:48:52 +0100 (Tue, 12 Mar 2019) $");
  script_tag(name:"creation_date", value:"2013-02-22 10:03:01 +0530 (Fri, 22 Feb 2013)");
  script_cve_id("CVE-2012-4546");
  script_bugtraq_id(58083);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_name("RedHat Update for ipa RHSA-2013:0528-02");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ipa'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_6");

  script_xref(name:"URL", value:"https://access.redhat.com/knowledge/articles/11258");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "RHENT_6")
{

  if ((res = isrpmvuln(pkg:"ipa-admintools", rpm:"ipa-admintools~3.0.0~25.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ipa-client", rpm:"ipa-client~3.0.0~25.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ipa-debuginfo", rpm:"ipa-debuginfo~3.0.0~25.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ipa-python", rpm:"ipa-python~3.0.0~25.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ipa-server", rpm:"ipa-server~3.0.0~25.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ipa-server-selinux", rpm:"ipa-server-selinux~3.0.0~25.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ipa-server-trust-ad", rpm:"ipa-server-trust-ad~3.0.0~25.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
