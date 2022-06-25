###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_kernel_sctp_prot_violation_dos_vuln.nasl 12669 2018-12-05 13:30:44Z cfischer $
#
# Linux Kernel Stream Control Transmission Protocol Violation Vulnerability
#
# Authors:
# Chandan S <schandan@secpod.com>
#
# Copyright:
# Copyright (c) 2008 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.800036");
  script_version("$Revision: 12669 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-05 14:30:44 +0100 (Wed, 05 Dec 2018) $");
  script_tag(name:"creation_date", value:"2008-10-22 15:17:54 +0200 (Wed, 22 Oct 2008)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_cve_id("CVE-2008-4618");
  script_bugtraq_id(31848);
  script_name("Linux Kernel Stream Control Transmission Protocol Violation Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2008/10/06/1");
  script_xref(name:"URL", value:"http://www.kernel.org/pub/linux/kernel/v2.6/ChangeLog-2.6.27");
  script_xref(name:"URL", value:"http://git.kernel.org/?p=linux/kernel/git/stable/linux-2.6.27.y.git;a=commit;h=ba0166708ef4da7eeb61dd92bbba4d5a749d6561");

  script_tag(name:"impact", value:"Successful attacks will result in denial of service via kernel related
  vectors.");

  script_tag(name:"affected", value:"Linux kernel version before 2.6.27 on all Linux Platforms.");

  script_tag(name:"insight", value:"The issue is with the parameter 'sctp_paramhdr' in sctp_sf_violation_paramlen,
  sctp_sf_abort_violation, and sctp_make_abort_violation functions of sm.h,
  sm_make_chunk.c, and sm_statefunc.c files, which has invalid length and
  incorrect data types in function calls.");

  script_tag(name:"summary", value:"This host has Linux Kernel Stream Control Transmission Protocol
  (SCTP) implementation and is prone to Protocol Violation Vulnerability.");

  script_tag(name:"solution", value:"Upgrade to Linux kernel 2.6.27, or
  apply the available patch from the referenced link.");

  script_tag(name:"deprecated", value:TRUE); # Covered by various LSCs and doesn't have much relevance these days...

  script_tag(name:"qod_type", value:"executable_version_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

exit(66);