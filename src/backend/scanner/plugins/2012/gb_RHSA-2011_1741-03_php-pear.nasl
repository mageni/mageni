###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for php-pear RHSA-2011:1741-03
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
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2011-December/msg00017.html");
  script_oid("1.3.6.1.4.1.25623.1.0.870625");
  script_version("$Revision: 14114 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-12 12:48:52 +0100 (Tue, 12 Mar 2019) $");
  script_tag(name:"creation_date", value:"2012-07-09 10:35:17 +0530 (Mon, 09 Jul 2012)");
  script_cve_id("CVE-2011-1072");
  script_tag(name:"cvss_base", value:"3.3");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:N/I:P/A:P");
  script_name("RedHat Update for php-pear RHSA-2011:1741-03");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'php-pear'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_6");
  script_tag(name:"affected", value:"php-pear on Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"The php-pear package contains the PHP Extension and Application Repository
  (PEAR), a framework and distribution system for reusable PHP components.

  It was found that the 'pear' command created temporary files in an insecure
  way when installing packages. A malicious, local user could use this flaw
  to conduct a symbolic link attack, allowing them to overwrite the contents
  of arbitrary files accessible to the victim running the 'pear install'
  command. (CVE-2011-1072)

  This update also fixes the following bugs:

  * The php-pear package has been upgraded to version 1.9.4, which provides a
  number of bug fixes over the previous version. (BZ#651897)

  * Prior to this update, php-pear created a cache in the
  '/var/cache/php-pear/' directory when attempting to list all packages. As a
  consequence, php-pear failed to create or update the cache file as a
  regular user without sufficient file permissions and could not list all
  packages. With this update, php-pear no longer fails if writing to the
  cache directory is not permitted. Now, all packages are listed as expected.
  (BZ#747361)

  All users of php-pear are advised to upgrade to this updated package, which
  corrects these issues.");
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

  if ((res = isrpmvuln(pkg:"php-pear", rpm:"php-pear~1.9.4~4.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
