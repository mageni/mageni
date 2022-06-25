###############################################################################
# OpenVAS Vulnerability Test
#
# Mandriva Update for mplayer MDVSA-2008:045 (mplayer)
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_insight = "Heap-based buffer overflow in the rmff_dump_cont function in
  input/libreal/rmff.c in xine-lib 1.1.9 and earlier allows remote
  attackers to execute arbitrary code via the SDP Abstract attribute,
  related to the rmff_dump_header function and related to disregarding
  the max field. Although originally a xine-lib issue, also affects
  MPlayer due to code similarity. (CVE-2008-0225)

  Multiple heap-based buffer overflows in the rmff_dump_cont function
  in input/libreal/rmff.c in xine-lib 1.1.9 allow remote attackers
  to execute arbitrary code via the SDP (1) Title, (2) Author, or
  (3) Copyright attribute, related to the rmff_dump_header function,
  different vectors than CVE-2008-0225. Although originally a xine-lib
  issue, also affects MPlayer due to code similarity. (CVE-2008-0238)
  
  Array index error in libmpdemux/demux_mov.c in MPlayer 1.0 rc2 and
  earlier might allow remote attackers to execute arbitrary code via
  a QuickTime MOV file with a crafted stsc atom tag. (CVE-2008-0485)
  
  Array index vulnerability in libmpdemux/demux_audio.c in MPlayer
  1.0rc2 and SVN before r25917, and possibly earlier versions, as
  used in Xine-lib 1.1.10, might allow remote attackers to execute
  arbitrary code via a crafted FLAC tag, which triggers a buffer
  overflow. (CVE-2008-0486)
  
  Buffer overflow in stream_cddb.c in MPlayer 1.0rc2 and SVN
  before r25824 allows remote user-assisted attackers to execute
  arbitrary code via a CDDB database entry containing a long album
  title. (CVE-2008-0629)
  
  Buffer overflow in url.c in MPlayer 1.0rc2 and SVN before r25823 allows
  remote attackers to execute arbitrary code via a crafted URL that
  prevents the IPv6 parsing code from setting a pointer to NULL, which
  causes the buffer to be reused by the unescape code. (CVE-2008-0630)
  
  The updated packages have been patched to prevent these issues.";

tag_affected = "mplayer on Mandriva Linux 2007.1,
  Mandriva Linux 2007.1/X86_64,
  Mandriva Linux 2008.0,
  Mandriva Linux 2008.0/X86_64";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "http://lists.mandriva.com/security-announce/2008-02/msg00022.php");
  script_oid("1.3.6.1.4.1.25623.1.0.306454");
  script_version("$Revision: 6568 $");
  script_tag(name:"last_modification", value:"$Date: 2017-07-06 15:04:21 +0200 (Thu, 06 Jul 2017) $");
  script_tag(name:"creation_date", value:"2009-04-09 14:26:37 +0200 (Thu, 09 Apr 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_xref(name: "MDVSA", value: "2008:045");
  script_cve_id("CVE-2008-0225", "CVE-2008-0238", "CVE-2008-0485", "CVE-2008-0486", "CVE-2008-0629", "CVE-2008-0630");
  script_name( "Mandriva Update for mplayer MDVSA-2008:045 (mplayer)");

  script_tag(name:"summary", value:"Check for the Version of mplayer");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Mandrake Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mandriva_mandrake_linux", "ssh/login/release");
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("pkg-lib-rpm.inc");

release = get_kb_item("ssh/login/release");


res = "";
if(release == NULL){
  exit(0);
}

if(release == "MNDK_2007.1")
{

  if ((res = isrpmvuln(pkg:"libdha1.0", rpm:"libdha1.0~1.0~1.rc1.11.5mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mencoder", rpm:"mencoder~1.0~1.rc1.11.5mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mplayer", rpm:"mplayer~1.0~1.rc1.11.5mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mplayer-doc", rpm:"mplayer-doc~1.0~1.rc1.11.5mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mplayer-gui", rpm:"mplayer-gui~1.0~1.rc1.11.5mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "MNDK_2008.0")
{

  if ((res = isrpmvuln(pkg:"libdha1.0", rpm:"libdha1.0~1.0~1.rc1.20.2mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mencoder", rpm:"mencoder~1.0~1.rc1.20.2mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mplayer", rpm:"mplayer~1.0~1.rc1.20.2mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mplayer-doc", rpm:"mplayer-doc~1.0~1.rc1.20.2mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mplayer-gui", rpm:"mplayer-gui~1.0~1.rc1.20.2mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
