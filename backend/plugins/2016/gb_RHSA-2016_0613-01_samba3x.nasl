###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for samba3x RHSA-2016:0613-01
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.871597");
  script_version("$Revision: 12497 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-04-13 05:17:13 +0200 (Wed, 13 Apr 2016)");
  script_cve_id("CVE-2015-5370", "CVE-2016-2110", "CVE-2016-2111", "CVE-2016-2112",
                "CVE-2016-2115", "CVE-2016-2118");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("RedHat Update for samba3x RHSA-2016:0613-01");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'samba3x'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Samba is an open-source implementation of
the Server Message Block (SMB) or Common Internet File System (CIFS) protocol,
which allows PC-compatible machines to share files, printers, and other information.

Security Fix(es):

  * Multiple flaws were found in Samba's DCE/RPC protocol implementation. A
remote, authenticated attacker could use these flaws to cause a denial of
service against the Samba server (high CPU load or a crash) or, possibly,
execute arbitrary code with the permissions of the user running Samba
(root). This flaw could also be used to downgrade a secure DCE/RPC
connection by a man-in-the-middle attacker taking control of an Active
Directory (AD) object and compromising the security of a Samba Active
Directory Domain Controller (DC). (CVE-2015-5370)

Note: While Samba packages as shipped in Red Hat Enterprise Linux do not
support running Samba as an AD DC, this flaw applies to all roles Samba
implements.

  * A protocol flaw, publicly referred to as Badlock, was found in the
Security Account Manager Remote Protocol (MS-SAMR) and the Local Security
Authority (Domain Policy) Remote Protocol (MS-LSAD). Any authenticated
DCE/RPC connection that a client initiates against a server could be used
by a man-in-the-middle attacker to impersonate the authenticated user
against the SAMR or LSA service on the server. As a result, the attacker
would be able to get read/write access to the Security Account Manager
database, and use this to reveal all passwords or any other potentially
sensitive information in that database. (CVE-2016-2118)

  * Several flaws were found in Samba's implementation of NTLMSSP
authentication. An unauthenticated, man-in-the-middle attacker could use
this flaw to clear the encryption and integrity flags of a connection,
causing data to be transmitted in plain text. The attacker could also force
the client or server into sending data in plain text even if encryption was
explicitly requested for that connection. (CVE-2016-2110)

  * It was discovered that Samba configured as a Domain Controller would
establish a secure communication channel with a machine using a spoofed
computer name. A remote attacker able to observe network traffic could use
this flaw to obtain session-related information about the spoofed machine.
(CVE-2016-2111)

  * It was found that Samba's LDAP implementation did not enforce integrity
protection for LDAP connections. A man-in-the-middle attacker could use
this flaw to downgrade LDAP connections to use no integrity protection,
allowing them to hijack such connections. (CVE-2016-2112)

  * It was found that Samba did not enable ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"affected", value:"samba3x on Red Hat Enterprise Linux (v. 5 server)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");

  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2016-April/msg00016.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_5");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "RHENT_5")
{

  if ((res = isrpmvuln(pkg:"samba3x", rpm:"samba3x~3.6.23~12.el5_11", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"samba3x-client", rpm:"samba3x-client~3.6.23~12.el5_11", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"samba3x-common", rpm:"samba3x-common~3.6.23~12.el5_11", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"samba3x-debuginfo", rpm:"samba3x-debuginfo~3.6.23~12.el5_11", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"samba3x-doc", rpm:"samba3x-doc~3.6.23~12.el5_11", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"samba3x-domainjoin-gui", rpm:"samba3x-domainjoin-gui~3.6.23~12.el5_11", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"samba3x-swat", rpm:"samba3x-swat~3.6.23~12.el5_11", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"samba3x-winbind", rpm:"samba3x-winbind~3.6.23~12.el5_11", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"samba3x-winbind-devel", rpm:"samba3x-winbind-devel~3.6.23~12.el5_11", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
