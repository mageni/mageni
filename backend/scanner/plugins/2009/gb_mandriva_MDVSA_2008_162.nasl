###############################################################################
# OpenVAS Vulnerability Test
#
# Mandriva Update for qemu MDVSA-2008:162 (qemu)
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
tag_insight = "Multiple vulnerabilities have been found in Qemu.

  Multiple heap-based buffer overflows in the cirrus_invalidate_region
  function in the Cirrus VGA extension in QEMU 0.8.2, as used in Xen and
  possibly other products, might allow local users to execute arbitrary
  code via unspecified vectors related to attempting to mark non-existent
  regions as dirty, aka the bitblt heap overflow. (CVE-2007-1320)
  
  Integer signedness error in the NE2000 emulator in QEMU 0.8.2,
  as used in Xen and possibly other products, allows local users to
  trigger a heap-based buffer overflow via certain register values
  that bypass sanity checks, aka QEMU NE2000 receive integer signedness
  error. (CVE-2007-1321)
  
  QEMU 0.8.2 allows local users to halt a virtual machine by executing
  the icebp instruction. (CVE-2007-1322)
  
  QEMU 0.8.2 allows local users to crash a virtual machine via the
  divisor operand to the aam instruction, as demonstrated by aam 0x0,
  which triggers a divide-by-zero error. (CVE-2007-1366)
  
  The NE2000 emulator in QEMU 0.8.2 allows local users to execute
  arbitrary code by writing Ethernet frames with a size larger than
  the MTU to the EN0_TCNT register, which triggers a heap-based
  buffer overflow in the slirp library, aka NE2000 mtu heap
  overflow. (CVE-2007-5729)
  
  Heap-based buffer overflow in QEMU 0.8.2, as used in Xen and possibly
  other products, allows local users to execute arbitrary code via
  crafted data in the net socket listen option, aka QEMU net socket
  heap overflow. (CVE-2007-5730)
  
  QEMU 0.9.0 allows local users of a Windows XP SP2 guest operating
  system to overwrite the TranslationBlock (code_gen_buffer) buffer,
  and probably have unspecified other impacts related to an overflow,
  via certain Windows executable programs, as demonstrated by
  qemu-dos.com. (CVE-2007-6227)
  
  Qemu 0.9.1 and earlier does not perform range checks for block
  device read or write requests, which allows guest host users with
  root privileges to access arbitrary memory and escape the virtual
  machine. (CVE-2008-0928)
  
  Changing removable media in QEMU could trigger a bug similar to
  CVE-2008-2004, which would allow local guest users to read arbitrary
  files on the host by modifying the header of the image to identify
  a different format. (CVE-2008-1945) See the diskformat: parameter to
  the -usbdevice option.
  
  The drive_init function in QEMU 0.9.1 determines the format of
  a raw disk image based on the header, which allows local guest
  users to read ar ... 

  Description truncated, for more information please check the Reference URL";

tag_affected = "qemu on Mandriva Linux 2008.0,
  Mandriva Linux 2008.0/X86_64,
  Mandriva Linux 2008.1,
  Mandriva Linux 2008.1/X86_64";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "http://lists.mandriva.com/security-announce/2008-08/msg00002.php");
  script_oid("1.3.6.1.4.1.25623.1.0.311045");
  script_version("$Revision: 6568 $");
  script_tag(name:"last_modification", value:"$Date: 2017-07-06 15:04:21 +0200 (Thu, 06 Jul 2017) $");
  script_tag(name:"creation_date", value:"2009-04-09 14:18:58 +0200 (Thu, 09 Apr 2009)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_xref(name: "MDVSA", value: "2008:162");
  script_cve_id("CVE-2007-1320", "CVE-2007-1321", "CVE-2007-1322", "CVE-2007-1366", "CVE-2007-5729", "CVE-2007-5730", "CVE-2007-6227", "CVE-2008-0928", "CVE-2008-2004", "CVE-2008-1945");
  script_name( "Mandriva Update for qemu MDVSA-2008:162 (qemu)");

  script_tag(name:"summary", value:"Check for the Version of qemu");
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

if(release == "MNDK_2008.0")
{

  if ((res = isrpmvuln(pkg:"dkms-kqemu", rpm:"dkms-kqemu~1.3.0~0.pre11.13.2mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qemu", rpm:"qemu~0.9.0~16.2mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qemu-img", rpm:"qemu-img~0.9.0~16.2mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "MNDK_2008.1")
{

  if ((res = isrpmvuln(pkg:"dkms-kqemu", rpm:"dkms-kqemu~1.3.0~0.pre11.15.2mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qemu", rpm:"qemu~0.9.0~18.2mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qemu-img", rpm:"qemu-img~0.9.0~18.2mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
