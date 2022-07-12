###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_RHSA-2017_2029-01_openssh.nasl 12497 2018-11-23 08:28:21Z cfischer $
#
# RedHat Update for openssh RHSA-2017:2029-01
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.871873");
  script_version("$Revision: 12497 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $");
  script_tag(name:"creation_date", value:"2017-08-04 12:47:29 +0530 (Fri, 04 Aug 2017)");
  script_cve_id("CVE-2016-10009", "CVE-2016-10011", "CVE-2016-10012", "CVE-2016-6210",
                "CVE-2016-6515");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("RedHat Update for openssh RHSA-2017:2029-01");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'openssh'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"OpenSSH is an SSH protocol implementation
  supported by a number of Linux, UNIX, and similar operating systems. It includes
  the core files necessary for both the OpenSSH client and server. The following
  packages have been upgraded to a later upstream version: openssh (7.4p1).
  (BZ#1341754) Security Fix(es): * A covert timing channel flaw was found in the
  way OpenSSH handled authentication of non-existent users. A remote
  unauthenticated attacker could possibly use this flaw to determine valid user
  names by measuring the timing of server responses. (CVE-2016-6210) * It was
  found that OpenSSH did not limit password lengths for password authentication. A
  remote unauthenticated attacker could use this flaw to temporarily trigger high
  CPU consumption in sshd by sending long passwords. (CVE-2016-6515) * It was
  found that ssh-agent could load PKCS#11 modules from arbitrary paths. An
  attacker having control of the forwarded agent-socket on the server, and the
  ability to write to the filesystem of the client host, could use this flaw to
  execute arbitrary code with the privileges of the user running ssh-agent.
  (CVE-2016-10009) * It was found that the host private key material could
  possibly leak to the privilege-separated child processes via re-allocated
  memory. An attacker able to compromise the privilege-separated process could
  therefore obtain the leaked key information. (CVE-2016-10011) * It was found
  that the boundary checks in the code implementing support for pre-authentication
  compression could have been optimized out by certain compilers. An attacker able
  to compromise the privilege-separated process could possibly use this flaw for
  further attacks against the privileged monitor process. (CVE-2016-10012)
  Additional Changes: For detailed information on changes in this release, see the
  Red Hat Enterprise Linux 7.4 Release Notes linked from the References section.");
  script_tag(name:"affected", value:"openssh on Red Hat Enterprise Linux Server (v. 7)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");

  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2017-August/msg00013.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
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

  if ((res = isrpmvuln(pkg:"openssh", rpm:"openssh~7.4p1~11.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openssh-askpass", rpm:"openssh-askpass~7.4p1~11.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openssh-clients", rpm:"openssh-clients~7.4p1~11.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openssh-debuginfo", rpm:"openssh-debuginfo~7.4p1~11.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openssh-keycat", rpm:"openssh-keycat~7.4p1~11.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openssh-server", rpm:"openssh-server~7.4p1~11.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}