###############################################################################
# OpenVAS Vulnerability Test
#
# Vulnerability in Microsoft DirectShow Could Allow Remote Code Execution
#
# Authors:
# Chandan S <schandan@secpod.com>
#
# Copyright (c) 2009 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.900097");
  script_version("2019-05-03T08:55:39+0000");
  script_tag(name:"deprecated", value:TRUE);
  script_tag(name:"last_modification", value:"2019-05-03 08:55:39 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2009-06-01 09:35:57 +0200 (Mon, 01 Jun 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-1537");
  script_bugtraq_id(35139);
  script_name("Vulnerability in Microsoft DirectShow Could Allow Remote Code Execution");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");

  script_xref(name:"URL", value:"http://www.microsoft.com/technet/security/bulletin/MS09-028.mspx");
  script_xref(name:"URL", value:"http://www.microsoft.com/technet/security/advisory/971778.mspx");

  script_tag(name:"impact", value:"Attacker who successfully exploit this flaw could take complete control of
  an affected system.");

  script_tag(name:"affected", value:"DirectX 7.0 8.1 and 9.0* on Microsoft Windows 2K

  DirectX 9.0 on Microsoft Windows XP and 2K3");

  script_tag(name:"insight", value:"Microsoft DirectShow fails to handle supported QuickTime format files. This
  could allow code execution if a user opened a specially crafted QuickTime
  media file when a user is logged on with administrative user rights.");

  script_tag(name:"summary", value:"This host is installed with Microsoft DirectShow and is prone to
  remote code execution vulnerability.

  This NVT has been replaced by OID:1.3.6.1.4.1.25623.1.0.900588.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

exit(66); ## This NVT is deprecated as addressed in secpod_ms09-028.nasl.