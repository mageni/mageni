###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_RHSA-2017_2459-01_libsoup.nasl 12497 2018-11-23 08:28:21Z cfischer $
#
# RedHat Update for libsoup RHSA-2017:2459-01
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
  script_oid("1.3.6.1.4.1.25623.1.0.871879");
  script_version("$Revision: 12497 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $");
  script_tag(name:"creation_date", value:"2017-08-11 07:21:23 +0200 (Fri, 11 Aug 2017)");
  script_cve_id("CVE-2017-2885");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("RedHat Update for libsoup RHSA-2017:2459-01");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'libsoup'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The libsoup packages provide an HTTP client
  and server library for GNOME. Security Fix(es): * A stack-based buffer overflow
  flaw was discovered within the HTTP processing of libsoup. A remote attacker
  could exploit this flaw to cause a crash or, potentially, execute arbitrary code
  by sending a specially crafted HTTP request to a server using the libsoup HTTP
  server functionality or by tricking a user into connecting to a malicious HTTP
  server with an application using the libsoup HTTP client functionality.
  (CVE-2017-2885) Red Hat would like to thank Aleksandar Nikolic (Cisco Talos) for
  reporting this issue.");
  script_tag(name:"affected", value:"libsoup on Red Hat Enterprise Linux Server (v. 7)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");

  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2017-August/msg00053.html");
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

  if ((res = isrpmvuln(pkg:"libsoup", rpm:"libsoup~2.56.0~4.el7_4", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libsoup-debuginfo", rpm:"libsoup-debuginfo~2.56.0~4.el7_4", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libsoup-devel", rpm:"libsoup-devel~2.56.0~4.el7_4", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}