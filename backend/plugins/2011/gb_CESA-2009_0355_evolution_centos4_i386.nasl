###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for evolution CESA-2009:0355 centos4 i386
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
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2009-May/015902.html");
  script_oid("1.3.6.1.4.1.25623.1.0.880920");
  script_version("$Revision: 14222 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $");
  script_tag(name:"creation_date", value:"2011-08-09 08:20:34 +0200 (Tue, 09 Aug 2011)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2009-0547", "CVE-2009-0582", "CVE-2009-0587");
  script_name("CentOS Update for evolution CESA-2009:0355 centos4 i386");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'evolution'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS4");
  script_tag(name:"affected", value:"evolution on CentOS 4");
  script_tag(name:"insight", value:"Evolution is the integrated collection of e-mail, calendaring, contact
  management, communications, and personal information management (PIM) tools
  for the GNOME desktop environment.

  Evolution Data Server provides a unified back-end for applications which
  interact with contacts, task and calendar information. Evolution Data
  Server was originally developed as a back-end for Evolution, but is now
  used by multiple other applications.

  Evolution did not properly check the Secure/Multipurpose Internet Mail
  Extensions (S/MIME) signatures used for public key encryption and signing
  of e-mail messages. An attacker could use this flaw to spoof a signature by
  modifying the text of the e-mail message displayed to the user. (CVE-2009-0547)

  It was discovered that evolution did not properly validate NTLM (NT LAN
  Manager) authentication challenge packets. A malicious server using NTLM
  authentication could cause evolution to disclose portions of its memory or
  crash during user authentication. (CVE-2009-0582)

  Multiple integer overflow flaws which could cause heap-based buffer
  overflows were found in the Base64 encoding routines used by evolution and
  evolution-data-server. This could cause evolution, or an application using
  evolution-data-server, to crash, or, possibly, execute an arbitrary code
  when large untrusted data blocks were Base64-encoded. (CVE-2009-0587)

  All users of evolution and evolution-data-server are advised to upgrade to
  these updated packages, which contain backported patches to correct these
  issues. All running instances of evolution and evolution-data-server must
  be restarted for the update to take effect.");
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

if(release == "CentOS4")
{

  if ((res = isrpmvuln(pkg:"evolution", rpm:"evolution~2.0.2~41.el4_7.2", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"evolution-data-server", rpm:"evolution-data-server~1.0.2~14.el4_7.1", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"evolution-data-server-devel", rpm:"evolution-data-server-devel~1.0.2~14.el4_7.1", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"evolution-devel", rpm:"evolution-devel~2.0.2~41.el4_7.2", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
