###############################################################################
# OpenVAS Vulnerability Test
#
# HP-UX Update for HP CIFS Server (Samba) HPSBUX02479
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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

include("revisions-lib.inc");
tag_impact = "Remote unauthorized access";
tag_affected = "HP CIFS Server (Samba) on
  HP CIFS Server vA.02.03.04 and vA.02.04 running on HP-UX B.11.11, B.11.23,
  or B.11.31.";
tag_insight = "A potential security vulnerability has been identified with HP-UX running HP
  CIFS Server (Samba). The vulnerability could be exploited to gain remote
  unauthorized access.";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "http://www11.itrc.hp.com/service/cki/docDisplay.do?docId=emr_na-c01940841");
  script_oid("1.3.6.1.4.1.25623.1.0.313778");
  script_version("$Revision: 8296 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-05 08:28:01 +0100 (Fri, 05 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-02-08 11:34:22 +0100 (Mon, 08 Feb 2010)");
  script_tag(name:"cvss_base", value:"6.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_xref(name: "HPSBUX", value: "02479");
  script_cve_id("CVE-2009-2813");
  script_name("HP-UX Update for HP CIFS Server (Samba) HPSBUX02479");

  script_tag(name: "summary" , value: "Check for the Version of HP CIFS Server (Samba)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("HP-UX Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/hp_hp-ux", "ssh/login/release");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("pkg-lib-hpux.inc");

release = get_kb_item("ssh/login/release");

res = "";
if(release == NULL){
  exit(0);
}

pkgs_rev = get_kb_item("ssh/login/hp_pkgrev");
ver = eregmatch(pattern:"CIFS-Server.CIFS-ADMIN[	 ]+(A.02.0[34])",string:pkgs_rev);

if(ver == NULL){
  exit(0);
}

if(release == "HPUX11.31")
{
  if (ver[1] == "A.02.04")
  {
    if ((res = ishpuxpkgvuln(pkg:"CIFS-Server.CIFS-ADMIN", revision:"A.02.04.01", rls:"HPUX11.31")) != NULL)
    {
      security_message(data:res);
      exit(0);
    }

    if ((res = ishpuxpkgvuln(pkg:"CIFS-Server.CIFS-DOC", revision:"A.02.04.01", rls:"HPUX11.31")) != NULL)
    {
      security_message(data:res);
      exit(0);
    }

    if ((res = ishpuxpkgvuln(pkg:"CIFS-Server.CIFS-LIB", revision:"A.02.04.01", rls:"HPUX11.31")) != NULL)
    {
      security_message(data:res);
      exit(0);
    }

    if ((res = ishpuxpkgvuln(pkg:"CIFS-Server.CIFS-MAN", revision:"A.02.04.01", rls:"HPUX11.31")) != NULL)
    {
      security_message(data:res);
      exit(0);
    }

    if ((res = ishpuxpkgvuln(pkg:"CIFS-Server.CIFS-RUN", revision:"A.02.04.01", rls:"HPUX11.31")) != NULL)
    {
      security_message(data:res);
      exit(0);
    }

    if ((res = ishpuxpkgvuln(pkg:"CIFS-Server.CIFS-UTIL", revision:"A.02.04.01", rls:"HPUX11.31")) != NULL)
    {
      security_message(data:res);
      exit(0);
    }
  }

  if (ver[1] == "A.02.03")
  {
    if ((res = ishpuxpkgvuln(pkg:"CIFS-Server.CIFS-ADMIN", revision:"A.02.03.05", rls:"HPUX11.31")) != NULL)
    {
      security_message(data:res);
      exit(0);
    }

    if ((res = ishpuxpkgvuln(pkg:"CIFS-Server.CIFS-DOC", revision:"A.02.03.05", rls:"HPUX11.31")) != NULL)
    {
      security_message(data:res);
      exit(0);
    }

    if ((res = ishpuxpkgvuln(pkg:"CIFS-Server.CIFS-LIB", revision:"A.02.03.05", rls:"HPUX11.31")) != NULL)
    {
      security_message(data:res);
      exit(0);
    }

    if ((res = ishpuxpkgvuln(pkg:"CIFS-Server.CIFS-RUN", revision:"A.02.03.05", rls:"HPUX11.31")) != NULL)
    {
      security_message(data:res);
      exit(0);
    }

    if ((res = ishpuxpkgvuln(pkg:"CIFS-Server.CIFS-UTIL", revision:"A.02.03.05", rls:"HPUX11.31")) != NULL)
    {
      security_message(data:res);
      exit(0);
    }
  }

  if ((res = ishpuxpkgvuln(pkg:"CIFS-CFSM.CFSM-KRN", revision:"A.02.03.05", rls:"HPUX11.31")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"CIFS-CFSM.CFSM-RUN", revision:"A.02.03.05", rls:"HPUX11.31")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "HPUX11.23")
{
  if (ver[1] == "A.02.04")
  {
    if ((res = ishpuxpkgvuln(pkg:"CIFS-Server.CIFS-ADMIN", revision:"A.02.04.01", rls:"HPUX11.23")) != NULL)
    {
      security_message(data:res);
      exit(0);
    }

    if ((res = ishpuxpkgvuln(pkg:"CIFS-Server.CIFS-DOC", revision:"A.02.04.01", rls:"HPUX11.23")) != NULL)
    {
      security_message(data:res);
      exit(0);
    }

    if ((res = ishpuxpkgvuln(pkg:"CIFS-Server.CIFS-LIB", revision:"A.02.04.01", rls:"HPUX11.23")) != NULL)
    {
      security_message(data:res);
      exit(0);
    }

    if ((res = ishpuxpkgvuln(pkg:"CIFS-Server.CIFS-MAN", revision:"A.02.04.01", rls:"HPUX11.23")) != NULL)
    {
      security_message(data:res);
      exit(0);
    }

    if ((res = ishpuxpkgvuln(pkg:"CIFS-Server.CIFS-RUN", revision:"A.02.04.01", rls:"HPUX11.23")) != NULL)
    {
      security_message(data:res);
      exit(0);
    }

    if ((res = ishpuxpkgvuln(pkg:"CIFS-Server.CIFS-UTIL", revision:"A.02.04.01", rls:"HPUX11.23")) != NULL)
    {
      security_message(data:res);
      exit(0);
    }
  }

  if (ver[1] == "A.02.03")
  {
    if ((res = ishpuxpkgvuln(pkg:"CIFS-Server.CIFS-ADMIN", revision:"A.02.03.05", rls:"HPUX11.23")) != NULL)
    {
      security_message(data:res);
      exit(0);
    }

    if ((res = ishpuxpkgvuln(pkg:"CIFS-Server.CIFS-DOC", revision:"A.02.03.05", rls:"HPUX11.23")) != NULL)
    {
      security_message(data:res);
      exit(0);
    }

    if ((res = ishpuxpkgvuln(pkg:"CIFS-Server.CIFS-LIB", revision:"A.02.03.05", rls:"HPUX11.23")) != NULL)
    {
      security_message(data:res);
      exit(0);
    }

    if ((res = ishpuxpkgvuln(pkg:"CIFS-Server.CIFS-RUN", revision:"A.02.03.05", rls:"HPUX11.23")) != NULL)
    {
      security_message(data:res);
      exit(0);
    }

    if ((res = ishpuxpkgvuln(pkg:"CIFS-Server.CIFS-UTIL", revision:"A.02.03.05", rls:"HPUX11.23")) != NULL)
    {
      security_message(data:res);
      exit(0);
    }
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "HPUX11.11")
{
  if (ver[1] == "A.02.04")
  {
    if ((res = ishpuxpkgvuln(pkg:"CIFS-Server.CIFS-ADMIN", revision:"A.02.04.01", rls:"HPUX11.11")) != NULL)
    {
      security_message(data:res);
      exit(0);
    }

    if ((res = ishpuxpkgvuln(pkg:"CIFS-Server.CIFS-DOC", revision:"A.02.04.01", rls:"HPUX11.11")) != NULL)
    {
      security_message(data:res);
      exit(0);
    }

    if ((res = ishpuxpkgvuln(pkg:"CIFS-Server.CIFS-LIB", revision:"A.02.04.01", rls:"HPUX11.11")) != NULL)
    {
      security_message(data:res);
      exit(0);
    }

    if ((res = ishpuxpkgvuln(pkg:"CIFS-Server.CIFS-MAN", revision:"A.02.04.01", rls:"HPUX11.11")) != NULL)
    {
      security_message(data:res);
      exit(0);
    }

    if ((res = ishpuxpkgvuln(pkg:"CIFS-Server.CIFS-RUN", revision:"A.02.04.01", rls:"HPUX11.11")) != NULL)
    {
      security_message(data:res);
      exit(0);
    }

    if ((res = ishpuxpkgvuln(pkg:"CIFS-Server.CIFS-UTIL", revision:"A.02.04.01", rls:"HPUX11.11")) != NULL)
    {
      security_message(data:res);
      exit(0);
    }
  }

  if (ver[1] == "A.02.03")
  {
    if ((res = ishpuxpkgvuln(pkg:"CIFS-Server.CIFS-ADMIN", revision:"A.02.03.05", rls:"HPUX11.11")) != NULL)
    {
      security_message(data:res);
      exit(0);
    }

    if ((res = ishpuxpkgvuln(pkg:"CIFS-Server.CIFS-DOC", revision:"A.02.03.05", rls:"HPUX11.11")) != NULL)
    {
      security_message(data:res);
      exit(0);
    }

    if ((res = ishpuxpkgvuln(pkg:"CIFS-Server.CIFS-LIB", revision:"A.02.03.05", rls:"HPUX11.11")) != NULL)
    {
      security_message(data:res);
      exit(0);
    }

    if ((res = ishpuxpkgvuln(pkg:"CIFS-Server.CIFS-RUN", revision:"A.02.03.05", rls:"HPUX11.11")) != NULL)
    {
      security_message(data:res);
      exit(0);
    }

    if ((res = ishpuxpkgvuln(pkg:"CIFS-Server.CIFS-UTIL", revision:"A.02.03.05", rls:"HPUX11.11")) != NULL)
    {
      security_message(data:res);
      exit(0);
    }
  }
  exit(0);
}
